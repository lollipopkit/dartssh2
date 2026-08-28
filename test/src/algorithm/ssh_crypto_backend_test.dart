import 'dart:typed_data';

import 'package:dartssh2/dartssh2.dart';
import 'package:pointycastle/api.dart';
import 'package:test/test.dart';

/// A backend that answers for the algorithms it is told to and `null` for the
/// rest, delegating the actual work back to pointycastle.
///
/// Delegating rather than computing something of its own is what lets these
/// tests assert on bytes: whatever comes out has to equal what the unmodified
/// library produces, so a wiring mistake shows up as wrong output rather than
/// as output nobody can check.
class _FakeBackend implements SSHCryptoBackend {
  _FakeBackend({this.ciphers = const {}, this.macs = const {}});

  final Set<String> ciphers;
  final Set<String> macs;

  final cipherCalls = <String>[];
  final macCalls = <(String, int)>[];

  @override
  BlockCipher? createBlockCipher(
    String algorithm,
    Uint8List key,
    Uint8List iv, {
    required bool forEncryption,
  }) {
    cipherCalls.add(algorithm);
    if (!ciphers.contains(algorithm)) return null;
    final type = SSHCipherType.fromName(algorithm)!;
    return _FakeBulkCipher(
      algorithm,
      _pointycastle(type, key, iv, forEncryption: forEncryption),
    );
  }

  @override
  Mac? createMac(String algorithm, Uint8List key, int macSize) {
    macCalls.add((algorithm, macSize));
    if (!macs.contains(algorithm)) return null;
    return _FakeMac(algorithm, macSize);
  }
}

/// The cipher [SSHCipherType.createCipher] would have built with no backend
/// installed.
BlockCipher _pointycastle(
  SSHCipherType type,
  Uint8List key,
  Uint8List iv, {
  required bool forEncryption,
}) {
  final previous = sshCryptoBackend;
  sshCryptoBackend = null;
  try {
    return type.createCipher(key, iv, forEncryption: forEncryption);
  } finally {
    sshCryptoBackend = previous;
  }
}

/// An ordinary [BlockCipher] that counts how often it is asked for a block and
/// otherwise delegates.
class _CountingCipher implements BlockCipher {
  _CountingCipher(this.algorithmName, this.inner);

  @override
  final String algorithmName;

  final BlockCipher inner;

  var blockCalls = 0;

  @override
  int get blockSize => inner.blockSize;

  @override
  Uint8List process(Uint8List data) => inner.process(data);

  @override
  int processBlock(Uint8List inp, int inpOff, Uint8List out, int outOff) {
    blockCalls++;
    return inner.processBlock(inp, inpOff, out, outOff);
  }

  @override
  void init(bool forEncryption, CipherParameters? params) =>
      throw StateError('keyed on creation');

  @override
  void reset() => throw StateError('keyed on creation');
}

/// The same, plus the bulk interface — which is the only difference
/// `BlockCipherX.processAll` dispatches on.
class _FakeBulkCipher extends _CountingCipher implements SSHBulkBlockCipher {
  _FakeBulkCipher(super.algorithmName, super.inner);

  var bulkCalls = 0;

  @override
  Uint8List processBulk(Uint8List data) {
    bulkCalls++;
    return inner.processAll(data);
  }
}

/// A MAC that is not a MAC — the tag is [macSize] copies of a fixed byte. These
/// tests are about which one gets built and with what, not about HMAC.
class _FakeMac implements Mac {
  _FakeMac(this.algorithmName, this.macSize);

  @override
  final String algorithmName;

  @override
  final int macSize;

  @override
  void init(CipherParameters params) => throw StateError('keyed on creation');

  @override
  void update(Uint8List inp, int inpOff, int len) {}

  @override
  void updateByte(int inp) {}

  @override
  int doFinal(Uint8List out, int outOff) {
    out.fillRange(outOff, outOff + macSize, 0xab);
    return macSize;
  }

  @override
  Uint8List process(Uint8List data) =>
      Uint8List(macSize)..fillRange(0, macSize, 0xab);

  @override
  void reset() {}
}

Uint8List _bytes(int length, [int seed = 1]) => Uint8List.fromList(
    List.generate(length, (i) => (i * 31 + seed * 17) & 0xff));

void main() {
  tearDown(() => sshCryptoBackend = null);

  group('with no backend installed', () {
    test('nothing changes', () {
      expect(sshCryptoBackend, isNull);
      final cipher = SSHCipherType.aes256ctr.createCipher(
        _bytes(32),
        _bytes(16),
        forEncryption: true,
      );
      expect(cipher, isNot(isA<SSHBulkBlockCipher>()));
      expect(SSHMacType.hmacSha256.createMac(_bytes(32)).macSize, 32);
    });
  });

  group('createCipher', () {
    test('uses what the backend returns', () {
      final backend = _FakeBackend(ciphers: {'aes256-ctr'});
      sshCryptoBackend = backend;

      final cipher = SSHCipherType.aes256ctr.createCipher(
        _bytes(32, 3),
        _bytes(16, 5),
        forEncryption: true,
      );

      expect(backend.cipherCalls, ['aes256-ctr']);
      expect(cipher, isA<SSHBulkBlockCipher>());
    });

    test('falls back to pointycastle when the backend answers null', () {
      final backend = _FakeBackend();
      sshCryptoBackend = backend;

      final cipher = SSHCipherType.aes256ctr.createCipher(
        _bytes(32, 3),
        _bytes(16, 5),
        forEncryption: true,
      );

      expect(backend.cipherCalls, ['aes256-ctr']);
      expect(cipher, isNot(isA<SSHBulkBlockCipher>()));

      sshCryptoBackend = null;
      final plain = SSHCipherType.aes256ctr.createCipher(
        _bytes(32, 3),
        _bytes(16, 5),
        forEncryption: true,
      );
      final packet = _bytes(64, 7);
      expect(cipher.processAll(packet), plain.processAll(packet));
    });

    test('is asked for the name as it appears on the wire', () {
      final backend = _FakeBackend();
      sshCryptoBackend = backend;

      for (final type in [
        SSHCipherType.aes128ctr,
        SSHCipherType.aes192ctr,
        SSHCipherType.aes256ctr,
        SSHCipherType.aes128cbc,
        SSHCipherType.aes192cbc,
        SSHCipherType.aes256cbc,
      ]) {
        type.createCipher(
          _bytes(type.keySize),
          _bytes(type.ivSize),
          forEncryption: true,
        );
      }

      expect(backend.cipherCalls, [
        'aes128-ctr',
        'aes192-ctr',
        'aes256-ctr',
        'aes128-cbc',
        'aes192-cbc',
        'aes256-cbc',
      ]);
    });

    test('a wrong key or IV length never reaches the backend', () {
      final backend = _FakeBackend(ciphers: {'aes256-ctr'});
      sshCryptoBackend = backend;

      expect(
        () => SSHCipherType.aes256ctr.createCipher(
          _bytes(16),
          _bytes(16),
          forEncryption: true,
        ),
        throwsArgumentError,
      );
      expect(
        () => SSHCipherType.aes256ctr.createCipher(
          _bytes(32),
          _bytes(12),
          forEncryption: true,
        ),
        throwsArgumentError,
      );
      expect(backend.cipherCalls, isEmpty);
    });

    test('an AEAD cipher is still refused before anything is built', () {
      final backend = _FakeBackend(ciphers: {'aes256-gcm@openssh.com'});
      sshCryptoBackend = backend;

      expect(
        () => SSHCipherType.aes256gcm.createCipher(
          _bytes(32),
          _bytes(12),
          forEncryption: true,
        ),
        throwsUnsupportedError,
      );
      expect(backend.cipherCalls, isEmpty);
    });
  });

  group('createMac', () {
    test('uses what the backend returns', () {
      final backend = _FakeBackend(macs: {'hmac-sha2-256'});
      sshCryptoBackend = backend;

      final mac = SSHMacType.hmacSha256.createMac(_bytes(32));

      expect(backend.macCalls, [('hmac-sha2-256', 32)]);
      expect(mac, isA<_FakeMac>());
    });

    test('falls back to pointycastle when the backend answers null', () {
      final backend = _FakeBackend();
      sshCryptoBackend = backend;

      final mac = SSHMacType.hmacSha256.createMac(_bytes(32, 11));
      expect(mac, isNot(isA<_FakeMac>()));

      sshCryptoBackend = null;
      final plain = SSHMacType.hmacSha256.createMac(_bytes(32, 11));
      final packet = _bytes(64, 2);
      expect(mac.process(packet), plain.process(packet));
    });

    test('is asked for the underlying hmac and the truncated size', () {
      final backend = _FakeBackend();
      sshCryptoBackend = backend;

      for (final type in [
        SSHMacType.hmacMd5,
        SSHMacType.hmacSha1,
        SSHMacType.hmacSha256,
        SSHMacType.hmacSha512,
        SSHMacType.hmacSha256_96,
        SSHMacType.hmacSha512_96,
        SSHMacType.hmacSha256Etm,
        SSHMacType.hmacSha512Etm,
      ]) {
        type.createMac(_bytes(type.keySize));
      }

      // The `-etm@openssh.com` suffix is about what gets fed in and `-96` about
      // what comes out, so neither reaches the backend as part of the name.
      expect(backend.macCalls, [
        ('hmac-md5', 16),
        ('hmac-sha1', 20),
        ('hmac-sha2-256', 32),
        ('hmac-sha2-512', 64),
        ('hmac-sha2-256', 12),
        ('hmac-sha2-512', 12),
        ('hmac-sha2-256', 32),
        ('hmac-sha2-512', 64),
      ]);
    });

    test('the declared size is what pointycastle produces', () {
      // What a backend is promised, checked against the implementation it
      // replaces — these two disagreeing would truncate or overrun a tag.
      for (final type in [
        SSHMacType.hmacMd5,
        SSHMacType.hmacSha1,
        SSHMacType.hmacSha256,
        SSHMacType.hmacSha512,
        SSHMacType.hmacSha256_96,
        SSHMacType.hmacSha512_96,
        SSHMacType.hmacSha256Etm,
        SSHMacType.hmacSha512Etm,
      ]) {
        expect(
          type.createMac(_bytes(type.keySize)).macSize,
          type.macSize,
          reason: type.name,
        );
      }
    });

    test('a wrong key length never reaches the backend', () {
      final backend = _FakeBackend(macs: {'hmac-sha2-256'});
      sshCryptoBackend = backend;

      expect(
        () => SSHMacType.hmacSha256.createMac(_bytes(16)),
        throwsArgumentError,
      );
      expect(backend.macCalls, isEmpty);
    });
  });

  group('processAll', () {
    test('hands a bulk cipher the whole packet in one call', () {
      final backend = _FakeBackend(ciphers: {'aes256-ctr'});
      sshCryptoBackend = backend;

      final cipher = SSHCipherType.aes256ctr.createCipher(
        _bytes(32, 3),
        _bytes(16, 5),
        forEncryption: true,
      ) as _FakeBulkCipher;

      cipher.processAll(_bytes(4096, 9));

      expect(cipher.bulkCalls, 1);
      expect(cipher.blockCalls, 0, reason: '256 blocks would be 256 calls');
    });

    test('still walks a plain cipher a block at a time', () {
      // The same wrapper without the bulk interface, which is the only thing
      // the dispatch looks at.
      final plain = _CountingCipher(
        'aes256-ctr',
        _pointycastle(
          SSHCipherType.aes256ctr,
          _bytes(32, 3),
          _bytes(16, 5),
          forEncryption: true,
        ),
      );
      expect(plain, isNot(isA<SSHBulkBlockCipher>()));

      final packet = _bytes(4096, 9);
      final walked = plain.processAll(packet);

      expect(plain.blockCalls, packet.length ~/ plain.blockSize);

      // And the two paths produce the same bytes, so the dispatch is a choice
      // of how rather than of what.
      final bulk = _FakeBulkCipher(
        'aes256-ctr',
        _pointycastle(
          SSHCipherType.aes256ctr,
          _bytes(32, 3),
          _bytes(16, 5),
          forEncryption: true,
        ),
      );
      expect(walked, bulk.processAll(packet));
      expect(bulk.bulkCalls, 1);
    });

    test('refuses an unaligned packet either way', () {
      final backend = _FakeBackend(ciphers: {'aes256-ctr'});
      sshCryptoBackend = backend;

      final bulk = SSHCipherType.aes256ctr.createCipher(
        _bytes(32, 3),
        _bytes(16, 5),
        forEncryption: true,
      );
      expect(
        () => bulk.processAll(_bytes(17)),
        throwsA(isA<FormatException>()),
      );

      sshCryptoBackend = null;
      final plain = SSHCipherType.aes256ctr.createCipher(
        _bytes(32, 3),
        _bytes(16, 5),
        forEncryption: true,
      );
      expect(
        () => plain.processAll(_bytes(17)),
        throwsA(isA<FormatException>()),
      );
    });
  });
}
