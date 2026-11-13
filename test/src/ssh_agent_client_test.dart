import 'dart:async';
import 'dart:typed_data';

import 'package:dartssh2/dartssh2.dart';
import 'package:dartssh2/src/hostkey/hostkey_ed25519.dart';
import 'package:dartssh2/src/message/base.dart';
import 'package:dartssh2/src/hostkey/hostkey_rsa.dart';
import 'package:test/test.dart';

import '../test_utils.dart';

/// The agent's end of a connection: frames are taken off the wire as they
/// arrive, and answered by [answer] in order.
class _Agent {
  _Agent(this._answer) {
    _toAgent.stream.listen((bytes) {
      _buffer.add(bytes);
      var all = _buffer.takeBytes();
      while (all.length >= 4) {
        final length = ByteData.sublistView(all, 0, 4).getUint32(0);
        if (all.length < 4 + length) break;
        _frames.add(Uint8List.sublistView(all, 4, 4 + length));
        unanswered++;
        if (unanswered > mostUnanswered) mostUnanswered = unanswered;
        all = Uint8List.sublistView(all, 4 + length);
      }
      _buffer.add(all);
      _drain();
    });
  }

  final Future<Uint8List> Function(Uint8List request) _answer;
  final _frames = <Uint8List>[];
  var _draining = false;

  /// Requests received and not yet answered, and the most there ever were.
  var unanswered = 0;
  var mostUnanswered = 0;

  Future<void> _drain() async {
    if (_draining) return;
    _draining = true;
    while (_frames.isNotEmpty) {
      final reply = await _answer(_frames.removeAt(0));
      unanswered--;
      send((BytesBuilder()
            ..add(
                (ByteData(4)..setUint32(0, reply.length)).buffer.asUint8List())
            ..add(reply))
          .takeBytes());
    }
    _draining = false;
  }

  final _toAgent = StreamController<List<int>>();
  final _toClient = StreamController<Uint8List>();
  final _buffer = BytesBuilder();

  late final socket = _Socket(_toClient.stream, _toAgent.sink);

  void send(List<int> bytes) => _toClient.add(Uint8List.fromList(bytes));

  Future<void> hangUp() => _toClient.close();
}

class _Socket implements SSHSocket {
  _Socket(this.stream, this.sink);

  @override
  final Stream<Uint8List> stream;

  @override
  final StreamSink<List<int>> sink;

  @override
  Future<void> get done => sink.done;

  @override
  Future<void> close() async => sink.close();

  @override
  void destroy() => sink.close();

  @override
  Future<void> flush() async {}
}

void main() {
  final ed25519 = SSHKeyPair.fromPem(fixture('ssh-ed25519/id_ed25519')).single;
  final rsa = SSHKeyPair.fromPem(fixture('ssh-rsa/id_rsa')).single;

  SSHAgentClient clientOf(SSHAgentHandler handler) =>
      SSHAgentClient(_Agent(handler.handleRequest).socket);

  test('lists the agent\'s keys with their comments', () async {
    final agent = clientOf(SSHKeyPairAgent([ed25519, rsa], comment: 'me@box'));

    final keys = await agent.identities();

    expect(keys.map((k) => k.keyType), ['ssh-ed25519', 'ssh-rsa']);
    expect(keys.map((k) => k.comment), ['me@box', 'me@box']);
    expect(keys.first.publicKey, ed25519.toPublicKey().encode());
  });

  test('an RSA key signs as rsa-sha2-256, which its type says', () async {
    final agent = clientOf(SSHKeyPairAgent([rsa]));
    final key = (await agent.identities()).single;
    final data = Uint8List.fromList([1, 2, 3]);

    expect(key.type, 'rsa-sha2-256');
    final signature = SSHRsaSignature.decode(await key.sign(data));
    expect(signature.type, SSHRsaSignatureType.sha256);
    expect(
      SSHRsaPublicKey.decode(key.publicKey).verify(data, signature),
      isTrue,
    );
  });

  test('an Ed25519 signature verifies against the listed key', () async {
    final agent = clientOf(SSHKeyPairAgent([ed25519]));
    final key = (await agent.identities()).single;
    final data = Uint8List.fromList([4, 5, 6]);

    expect(key.type, 'ssh-ed25519');
    final signature = SSHEd25519Signature.decode(await key.sign(data));
    expect(
      SSHEd25519PublicKey.decode(key.publicKey).verify(data, signature),
      isTrue,
    );
  });

  test('one request is on the wire at a time', () async {
    final real = SSHKeyPairAgent([ed25519]);
    final end = _Agent((request) async {
      await Future<void>.delayed(const Duration(milliseconds: 5));
      return real.handleRequest(request);
    });
    final agent = SSHAgentClient(end.socket);

    final key = (await agent.identities()).single;
    final results = await Future.wait([
      agent.identities(),
      key.sign(Uint8List(1)),
      agent.identities(),
    ]);

    expect(end.mostUnanswered, 1);
    expect(results[0], isA<List<SSHAgentIdentity>>());
    expect(results[1], isA<Uint8List>());
    expect(results[2], isA<List<SSHAgentIdentity>>());
  });

  test('a key the agent does not hold is a refusal', () async {
    final agent = clientOf(SSHKeyPairAgent([ed25519]));

    await expectLater(
      agent.sign(rsa.toPublicKey().encode(), Uint8List(1)),
      throwsA(isA<SSHAgentError>()),
    );
    // The connection still serves.
    expect(await agent.identities(), hasLength(1));
  });

  test('an agent that hangs up fails what waits, and what comes after',
      () async {
    final never = Completer<Uint8List>();
    final end = _Agent((_) => never.future);
    final agent = SSHAgentClient(end.socket);

    final waiting = agent.identities();
    await Future<void>.delayed(Duration.zero);
    await end.hangUp();

    await expectLater(waiting, throwsA(isA<SSHAgentError>()));
    await expectLater(agent.identities(), throwsA(isA<SSHAgentError>()));
  });

  test('a frame longer than the protocol allows ends the connection', () async {
    final never = Completer<Uint8List>();
    final end = _Agent((_) => never.future);
    final agent = SSHAgentClient(end.socket);

    final waiting = agent.identities();
    await Future<void>.delayed(Duration.zero);
    end.send([0xff, 0xff, 0xff, 0xff]);

    await expectLater(waiting, throwsA(isA<SSHAgentError>()));
  });

  test('a malformed list is an agent error', () async {
    final agent = SSHAgentClient(_Agent((_) async {
      return Uint8List.fromList(
          [SSHAgentProtocol.identitiesAnswer, 0, 0, 0, 9]);
    }).socket);

    await expectLater(agent.identities(), throwsA(isA<SSHAgentError>()));
  });

  test('an unanswered request ends the connection, and what waits behind it',
      () async {
    final never = Completer<Uint8List>();
    final end = _Agent((_) => never.future);
    final agent = SSHAgentClient(
      end.socket,
      timeout: const Duration(milliseconds: 50),
    );
    final watch = Stopwatch()..start();

    await Future.wait([
      expectLater(agent.identities(), throwsA(isA<SSHAgentError>())),
      expectLater(agent.identities(), throwsA(isA<SSHAgentError>())),
    ]);
    expect(watch.elapsed, lessThan(const Duration(seconds: 1)));
  });

  test('an RSA signature that is not SHA-2 is refused', () async {
    final real = SSHKeyPairAgent([rsa]);
    final agent = SSHAgentClient(_Agent((request) {
      // An agent that ignores the flags: SHA-1.
      final r = SSHMessageReader(request);
      if (r.readUint8() == SSHAgentProtocol.signRequest) {
        final w = SSHMessageWriter()
          ..writeUint8(SSHAgentProtocol.signRequest)
          ..writeString(r.readString())
          ..writeString(r.readString())
          ..writeUint32(0);
        return real.handleRequest(w.takeBytes());
      }
      return real.handleRequest(request);
    }).socket);
    final key = (await agent.identities()).single;

    await expectLater(key.sign(Uint8List(1)), throwsA(isA<SSHAgentError>()));
  });

  test('a comment that is not UTF-8 still lists its key', () async {
    final blob = ed25519.toPublicKey().encode();
    final agent = SSHAgentClient(_Agent((_) async {
      final w = SSHMessageWriter()
        ..writeUint8(SSHAgentProtocol.identitiesAnswer)
        ..writeUint32(2)
        ..writeString(blob)
        ..writeString(Uint8List.fromList([0xff, 0xfe]))
        ..writeString(Uint8List.fromList([0, 0, 0, 9]))
        ..writeString(Uint8List(0));
      return w.takeBytes();
    }).socket);

    final keys = await agent.identities();

    expect(keys.single.publicKey, blob);
  });
}
