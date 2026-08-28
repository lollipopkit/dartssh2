// A non-ETM inbound packet whose encrypted portion is not a whole number of
// blocks. SSH requires it to be one, so this is a malformed packet — and the
// ETM path has always reported it as `SSHPacketError`. The non-ETM path used to
// decrypt a block at a time, which absorbed the mismatch by reading a block
// past the packet and into the MAC; it now decrypts the remainder in one call,
// which would raise `FormatException` from `processAll` and reach the caller as
// `SSHInternalError`. This pins both paths on the same error.

import 'dart:async';
import 'dart:mirrors';
import 'dart:typed_data';

import 'package:dartssh2/dartssh2.dart';
import 'package:test/test.dart';

void main() {
  final transportLibrary = reflectClass(SSHTransport).owner as LibraryMirror;
  void setPrivate(SSHTransport transport, String field, Object? value) {
    reflect(transport).setField(
      MirrorSystem.getSymbol(field, transportLibrary),
      value,
    );
  }

  /// A receiver keyed for `aes256-ctr` with a plain (non-ETM) HMAC.
  (SSHTransport, _FeedSSHSocket) receiver(Uint8List key, Uint8List iv) {
    final socket = _FeedSSHSocket();
    final transport = SSHTransport(
      socket,
      algorithms: const SSHAlgorithms(
        cipher: [SSHCipherType.aes256ctr],
        mac: [SSHMacType.hmacSha256],
      ),
    );
    setPrivate(transport, '_remoteVersion', 'SSH-2.0-test');
    setPrivate(transport, '_serverCipherType', SSHCipherType.aes256ctr);
    setPrivate(transport, '_serverMacType', SSHMacType.hmacSha256);
    setPrivate(
      transport,
      '_decryptCipher',
      SSHCipherType.aes256ctr.createCipher(key, iv, forEncryption: false),
    );
    setPrivate(
      transport,
      '_remoteMac',
      SSHMacType.hmacSha256.createMac(Uint8List(SSHMacType.hmacSha256.keySize)),
    );
    return (transport, socket);
  }

  /// [packetLength] in the first block, encrypted, followed by enough bytes for
  /// the transport to believe the whole packet and its MAC have arrived.
  Uint8List packetClaiming(int packetLength, Uint8List key, Uint8List iv) {
    final first = Uint8List(16);
    first.buffer.asByteData().setUint32(0, packetLength);
    final encrypted = SSHCipherType.aes256ctr
        .createCipher(key, iv, forEncryption: true)
        .processAll(first);
    final rest = Uint8List(
      4 + packetLength + SSHMacType.hmacSha256.macSize - encrypted.length,
    );
    return Uint8List.fromList([...encrypted, ...rest]);
  }

  test('an unaligned non-ETM packet is an SSHPacketError', () async {
    final key = Uint8List.fromList(List.generate(32, (i) => i));
    final iv = Uint8List.fromList(List.generate(16, (i) => i + 32));

    // 4 + 20 is 24, which is not a multiple of the 16-byte block. Inside
    // `_verifyPacketLength`'s bounds, so it gets as far as being decrypted.
    final (transport, socket) = receiver(key, iv);
    socket.feed(packetClaiming(20, key, iv));

    await expectLater(
      transport.done,
      throwsA(
        isA<SSHPacketError>().having(
          (e) => e.message,
          'message',
          contains('not a multiple of block size'),
        ),
      ),
    );
  });

  test('an aligned one gets past the length check', () async {
    final key = Uint8List.fromList(List.generate(32, (i) => i));
    final iv = Uint8List.fromList(List.generate(16, (i) => i + 32));

    // 4 + 28 is 32. The bytes are not a real packet, so this still fails — on
    // the MAC or the padding, which is the point: not on the alignment.
    final (transport, socket) = receiver(key, iv);
    socket.feed(packetClaiming(28, key, iv));

    await expectLater(
      transport.done,
      throwsA(
        isA<SSHError>().having(
          (e) => e.toString(),
          'toString',
          isNot(contains('not a multiple of block size')),
        ),
      ),
    );
  });
}

/// A socket that hands the transport bytes and swallows what it writes.
class _FeedSSHSocket implements SSHSocket {
  final _incoming = StreamController<Uint8List>();
  final _outgoing = StreamController<List<int>>();

  void feed(Uint8List bytes) => _incoming.add(bytes);

  @override
  Stream<Uint8List> get stream => _incoming.stream;

  @override
  StreamSink<List<int>> get sink => _outgoing.sink;

  @override
  Future<void> get done => _incoming.done;

  @override
  Future<void> close() async {
    await _incoming.close();
    await _outgoing.close();
  }

  @override
  Future<void> flush() async {}

  @override
  void destroy() {
    _incoming.close();
    _outgoing.close();
  }
}
