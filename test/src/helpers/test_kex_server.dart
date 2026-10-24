import 'dart:async';

import 'package:dartssh2/dartssh2.dart';
import 'package:dartssh2/src/hostkey/hostkey_ed25519.dart';
import 'package:dartssh2/src/kex/kex_x25519.dart';
import 'package:dartssh2/src/message/base.dart';
import 'package:dartssh2/src/ssh_kex_utils.dart';
import 'package:dartssh2/src/ssh_transport.dart';
import 'package:pinenacl/ed25519.dart';
import 'package:pointycastle/digests/sha256.dart';

/// The server's half of a curve25519 exchange, played by a test: the library
/// has only the client's.
class TestKexServer {
  static const version = 'SSH-2.0-TestServer';

  final Uint8List kexInit;

  TestKexServer({List<String> hostKeyAlgorithms = const ['ssh-ed25519']})
      : kexInit = SSH_Message_KexInit(
          kexAlgorithms: [SSHKexType.x25519Rfc.name],
          serverHostKeyAlgorithms: hostKeyAlgorithms,
          encryptionClientToServer: [SSHCipherType.aes128ctr.name],
          encryptionServerToClient: [SSHCipherType.aes128ctr.name],
          macClientToServer: [SSHMacType.hmacSha256.name],
          macServerToClient: [SSHMacType.hmacSha256.name],
          compressionClientToServer: const ['none'],
          compressionServerToClient: const ['none'],
          firstKexPacketFollows: false,
        ).encode();

  /// A client transport to run exchanges against.
  static SSHTransport client({
    SSHHostkeyVerifyHandler? onVerifyHostKey,
    SSHHostCertificateTrust? hostCertificateTrust,
  }) =>
      SSHTransport(
        _NullSocket(),
        onVerifyHostKey: onVerifyHostKey,
        hostCertificateTrust: hostCertificateTrust,
      )..receivedVersion(version);

  /// One exchange through to NEWKEYS: [hostKey] presented — the plain key of
  /// [signer] unless given, e.g. a certificate for it — and signed by
  /// [signer].
  Future<void> exchange(
    SSHTransport transport, {
    required SigningKey signer,
    Uint8List? hostKey,
  }) async {
    await transport.handleMessageKexInit(kexInit);
    final clientPublic = transport.kexPublicKey!;
    final server = SSHKexX25519();
    final hostBlob = hostKey ?? ed25519PublicKey(signer);
    final hash = SSHKexUtils.computeExchangeHash(
      digest: SHA256Digest(),
      clientVersion: transport.localVersion,
      serverVersion: version,
      clientKexInit: transport.localKexInit!,
      serverKexInit: kexInit,
      hostKey: hostBlob,
      clientPublicKey: clientPublic,
      serverPublicKey: server.publicKey,
      sharedSecret: server.computeSecret(clientPublic),
    );
    await transport.handleMessageKexReply(
      SSH_Message_KexECDH_Reply(
        hostPublicKey: hostBlob,
        ecdhPublicKey: server.publicKey,
        signature: _sign(signer, hash),
      ).encode(),
    );
    await transport.handleMessageNewKeys();
  }
}

Uint8List ed25519PublicKey(SigningKey key) =>
    SSHEd25519PublicKey(key.verifyKey.asTypedList).encode();

/// An Ed25519 host certificate for [host], signed by [ca]
/// (PROTOCOL.certkeys). Times are seconds since the epoch; [validBefore]
/// null is "forever".
Uint8List ed25519HostCertificate({
  required SigningKey host,
  required SigningKey ca,
  List<String> principals = const [],
  int certType = 2,
  int validAfter = 0,
  int? validBefore,
}) {
  final principalList = SSHMessageWriter();
  for (final name in principals) {
    principalList.writeUtf8(name);
  }
  final writer = SSHMessageWriter()
    ..writeUtf8('ssh-ed25519-cert-v01@openssh.com')
    ..writeString(Uint8List(32)) // nonce
    ..writeString(host.verifyKey.asTypedList)
    ..writeUint64(0) // serial
    ..writeUint32(certType)
    ..writeUtf8('test')
    ..writeString(principalList.takeBytes())
    ..writeUint64(validAfter);
  if (validBefore == null) {
    writer
      ..writeUint32(0xFFFFFFFF)
      ..writeUint32(0xFFFFFFFF);
  } else {
    writer.writeUint64(validBefore);
  }
  writer
    ..writeString(Uint8List(0)) // critical options
    ..writeString(Uint8List(0)) // extensions
    ..writeString(Uint8List(0)) // reserved
    ..writeString(ed25519PublicKey(ca));
  final signed = writer.takeBytes();
  return (SSHMessageWriter()
        ..writeBytes(signed)
        ..writeString(_sign(ca, signed)))
      .takeBytes();
}

Uint8List _sign(SigningKey key, Uint8List message) =>
    SSHEd25519Signature(key.sign(message).signature.asTypedList).encode();

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
