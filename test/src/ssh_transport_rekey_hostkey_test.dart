import 'dart:async';

import 'package:dartssh2/dartssh2.dart';
import 'package:dartssh2/src/hostkey/hostkey_ed25519.dart';
import 'package:dartssh2/src/kex/kex_x25519.dart';
import 'package:dartssh2/src/message/base.dart';
import 'package:dartssh2/src/ssh_kex_utils.dart';
import 'package:dartssh2/src/ssh_transport.dart';
import 'package:pinenacl/ed25519.dart';
import 'package:pointycastle/digests/sha256.dart';
import 'package:test/test.dart';

/// A re-key brings the host key along again, and it has to be the one the
/// user was asked about. This test plays the server's half of a
/// curve25519/Ed25519 exchange itself — the library has only the client's.
void main() {
  const serverVersion = 'SSH-2.0-TestServer';
  final serverKexInit = SSH_Message_KexInit(
    kexAlgorithms: [SSHKexType.x25519Rfc.name],
    serverHostKeyAlgorithms: [SSHHostkeyType.ed25519.name],
    encryptionClientToServer: [SSHCipherType.aes128ctr.name],
    encryptionServerToClient: [SSHCipherType.aes128ctr.name],
    macClientToServer: [SSHMacType.hmacSha256.name],
    macServerToClient: [SSHMacType.hmacSha256.name],
    compressionClientToServer: const ['none'],
    compressionServerToClient: const ['none'],
    firstKexPacketFollows: false,
  ).encode();

  late SSHTransport transport;
  late int asked;

  setUp(() {
    asked = 0;
    transport = SSHTransport(
      _NullSocket(),
      onVerifyHostKey: (type, fingerprint) {
        asked++;
        return true;
      },
    )..receivedVersion(serverVersion);
  });

  tearDown(() => transport.close());

  /// One exchange, answered with [hostKey], through to NEWKEYS.
  Future<void> exchange(SigningKey hostKey) async {
    await transport.handleMessageKexInit(serverKexInit);
    final clientPublic = transport.kexPublicKey!;
    final server = SSHKexX25519();
    final hostBlob =
        SSHEd25519PublicKey(hostKey.verifyKey.asTypedList).encode();
    final hash = SSHKexUtils.computeExchangeHash(
      digest: SHA256Digest(),
      clientVersion: transport.localVersion,
      serverVersion: serverVersion,
      clientKexInit: transport.localKexInit!,
      serverKexInit: serverKexInit,
      hostKey: hostBlob,
      clientPublicKey: clientPublic,
      serverPublicKey: server.publicKey,
      sharedSecret: server.computeSecret(clientPublic),
    );
    final signature =
        SSHEd25519Signature(hostKey.sign(hash).signature.asTypedList).encode();
    await transport.handleMessageKexReply(
      SSH_Message_KexECDH_Reply(
        hostPublicKey: hostBlob,
        ecdhPublicKey: server.publicKey,
        signature: signature,
      ).encode(),
    );
    await transport.handleMessageNewKeys();
  }

  test('a re-key with the same host key goes through without asking again',
      () async {
    final hostKey = SigningKey.generate();
    await exchange(hostKey);
    expect(asked, 1);

    await exchange(hostKey);
    expect(asked, 1);
  });

  test('a re-key with another host key is refused, not asked about', () async {
    await exchange(SigningKey.generate());
    expect(asked, 1);

    await expectLater(
      exchange(SigningKey.generate()),
      throwsA(isA<SSHHostkeyError>().having(
        (e) => e.message,
        'message',
        contains('changed during re-key'),
      )),
    );
    expect(asked, 1);
  });
}

/// Swallows what the transport sends; nothing is read back from it.
class _NullSocket implements SSHSocket {
  final _incoming = StreamController<Uint8List>();
  final _done = Completer<void>();

  @override
  Stream<Uint8List> get stream => _incoming.stream;

  @override
  StreamSink<List<int>> get sink => _NullSink();

  @override
  Future<void> get done => _done.future;

  @override
  Future<void> close() async {
    if (!_done.isCompleted) _done.complete();
    await _incoming.close();
  }

  @override
  void destroy() => unawaited(close());

  @override
  Future<void> flush() async {}
}

class _NullSink implements StreamSink<List<int>> {
  @override
  void add(List<int> data) {}

  @override
  void addError(Object error, [StackTrace? stackTrace]) {}

  @override
  Future addStream(Stream<List<int>> stream) => stream.drain();

  @override
  Future close() async {}

  @override
  Future get done => Future.value();
}
