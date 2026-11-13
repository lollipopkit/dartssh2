import 'dart:async';
import 'dart:collection';
import 'dart:typed_data';

import 'package:dartssh2/src/message/base.dart';
import 'package:dartssh2/src/socket/ssh_socket.dart';
import 'package:dartssh2/src/ssh_agent.dart';
import 'package:dartssh2/src/ssh_errors.dart';
import 'package:dartssh2/src/ssh_signer.dart';

/// The client half of the ssh-agent protocol (draft-miller-ssh-agent): lists
/// the keys an agent the user runs holds, and has it sign with them. The
/// private keys never leave the agent.
///
/// One request is on the wire at a time; the next is sent once the previous
/// is answered.
class SSHAgentClient {
  SSHAgentClient(this._socket, {this.timeout = defaultTimeout}) {
    _subscription = _socket.stream.listen(
      _handleData,
      onError: (Object e) => _fail(SSHAgentError('connection failed: $e')),
      onDone: () => _fail(SSHAgentError('connection closed')),
    );
  }

  /// How long one answer may take. An agent may be waiting on the user (a
  /// touch, a fingerprint), so this is generous, and under sshd's default
  /// `LoginGraceTime` of two minutes.
  ///
  /// The protocol cannot cancel a request, and the agent answers in order, so
  /// a connection whose request went unanswered can answer nothing after it:
  /// it is closed, and every request after fails at once rather than waiting
  /// behind it.
  final Duration timeout;

  static const defaultTimeout = Duration(minutes: 1);

  final SSHSocket _socket;
  late final StreamSubscription<Uint8List> _subscription;

  final _frames = SSHAgentFrames();
  final _waiting = Queue<Completer<Uint8List>>();
  Future<void> _tail = Future.value();
  SSHAgentError? _closed;

  /// Every key the agent offers, in the agent's order. A key whose blob does
  /// not name its type is left out.
  Future<List<SSHAgentIdentity>> identities() async {
    final reader = await _request(
      Uint8List.fromList([SSHAgentProtocol.requestIdentities]),
      SSHAgentProtocol.identitiesAnswer,
    );
    final entries = _parse(() {
      final count = reader.readUint32();
      return [
        for (var i = 0; i < count; i++)
          (reader.readString(), reader.readUtf8(allowMalformed: true)),
      ];
    });
    return [
      for (final (blob, comment) in entries)
        if (_keyType(blob) case final type?)
          SSHAgentIdentity._(this, blob, comment, type),
    ];
  }

  /// The encoded signature blob the agent makes over [data] with the key
  /// whose blob is [publicKey]. [flags] picks an RSA hash
  /// ([SSHAgentProtocol.rsaSha2_256], [SSHAgentProtocol.rsaSha2_512]).
  Future<Uint8List> sign(
    Uint8List publicKey,
    Uint8List data, {
    int flags = 0,
  }) async {
    final request = SSHMessageWriter()
      ..writeUint8(SSHAgentProtocol.signRequest)
      ..writeString(publicKey)
      ..writeString(data)
      ..writeUint32(flags);
    final reader =
        await _request(request.takeBytes(), SSHAgentProtocol.signResponse);
    return _parse(reader.readString);
  }

  Future<void> close() async {
    _fail(SSHAgentError('closed'));
    await _subscription.cancel();
    await _socket.close();
  }

  Future<SSHMessageReader> _request(Uint8List payload, int answer) {
    final reply = _tail.then((_) {
      final closed = _closed;
      if (closed != null) throw closed;
      _socket.sink.add(SSHAgentFrames.encode(payload));
      final completer = Completer<Uint8List>();
      _waiting.add(completer);
      return completer.future.timeout(timeout, onTimeout: () {
        final error =
            SSHAgentError('no answer in ${timeout.inMilliseconds} ms');
        _fail(error);
        _socket.destroy();
        throw error;
      });
    });
    _tail = reply.then<void>((_) {}, onError: (_) {});
    return reply.then((bytes) {
      final reader = SSHMessageReader(bytes);
      final type = _parse(reader.readUint8);
      if (type == SSHAgentProtocol.failure) {
        throw SSHAgentError('the agent refused the request');
      }
      if (type != answer) throw SSHAgentError('unexpected reply $type');
      return reader;
    });
  }

  void _handleData(Uint8List data) {
    try {
      for (final frame in _frames.add(data)) {
        if (_waiting.isEmpty) {
          throw SSHAgentError('a reply nothing asked for');
        }
        _waiting.removeFirst().complete(frame);
      }
    } on SSHAgentError catch (e) {
      _fail(e);
      _socket.destroy();
    }
  }

  void _fail(SSHAgentError error) {
    _closed ??= error;
    while (_waiting.isNotEmpty) {
      _waiting.removeFirst().completeError(error);
    }
  }

  static String? _keyType(Uint8List blob) {
    try {
      return SSHMessageReader(blob).readUtf8();
    } on RangeError {
      return null;
    } on FormatException {
      return null;
    }
  }

  static T _parse<T>(T Function() read) {
    try {
      return read();
    } on RangeError {
      throw SSHAgentError('malformed reply');
    } on FormatException {
      throw SSHAgentError('malformed reply');
    }
  }
}

/// A key an agent holds, offered for `publickey` authentication.
class SSHAgentIdentity implements SSHSigner {
  SSHAgentIdentity._(this._agent, this.publicKey, this.comment, this.keyType);

  final SSHAgentClient _agent;

  @override
  final Uint8List publicKey;

  /// What the key's owner called it when adding it, often a path or an email.
  final String comment;

  /// The type the key blob names, such as `ssh-ed25519` or `ssh-rsa`.
  final String keyType;

  bool get _isRsa =>
      keyType == 'ssh-rsa' || keyType == 'ssh-rsa-cert-v01@openssh.com';

  /// RSA signs with SHA-256, as an in-app RSA key does: `ssh-rsa` itself
  /// means SHA-1, which current servers refuse.
  @override
  String get type => switch (keyType) {
        'ssh-rsa' => 'rsa-sha2-256',
        'ssh-rsa-cert-v01@openssh.com' => 'rsa-sha2-256-cert-v01@openssh.com',
        _ => keyType,
      };

  @override
  Future<Uint8List> sign(Uint8List data) async {
    final signature = await _agent.sign(
      publicKey,
      data,
      flags: _isRsa ? SSHAgentProtocol.rsaSha2_256 : 0,
    );
    // An agent that ignores the flag signs SHA-1, which the server would
    // refuse with no reason given.
    if (_isRsa) {
      final signed = SSHAgentClient._keyType(signature);
      if (signed != 'rsa-sha2-256') {
        throw SSHAgentError('the agent signed $signed, not rsa-sha2-256');
      }
    }
    return signature;
  }

  @override
  String toString() => 'SSHAgentIdentity($keyType, $comment)';
}
