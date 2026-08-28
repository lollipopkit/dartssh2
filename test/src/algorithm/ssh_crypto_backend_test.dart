import 'dart:typed_data';

import 'package:dartssh2/dartssh2.dart';
// Not exported from the barrel.
// ignore_for_file: implementation_imports
import 'package:dartssh2/src/hostkey/hostkey_ecdsa.dart';
import 'package:dartssh2/src/hostkey/hostkey_ed25519.dart';
import 'package:dartssh2/src/kex/kex_x25519.dart';
import 'package:dartssh2/src/utils/bcrypt.dart' as builtin;
import 'package:dartssh2/src/utils/bigint.dart';
import 'package:pointycastle/api.dart';
import 'package:test/test.dart';

/// A backend that answers for the algorithms it is told to and `null` for the
/// rest, delegating the actual work back to pointycastle.
///
/// Delegating rather than computing something of its own is what lets these
/// tests assert on bytes: whatever comes out has to equal what the unmodified
/// library produces, so a wiring mistake shows up as wrong output rather than
/// as output nobody can check.
// `extends`, not `implements`: the defaults are what make an unimplemented
// operation fall back to the built-in, and that is what most of a backend is.
class _FakeBackend extends SSHCryptoBackend {
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
  _asymTests();

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

const _ed25519Pem = '''
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACAmeIqTaKVgK3jyqh4LHAn/4XF3L+mFu2FuSIb2WCRxQwAAAIjjp0Dr46dA
6wAAAAtzc2gtZWQyNTUxOQAAACAmeIqTaKVgK3jyqh4LHAn/4XF3L+mFu2FuSIb2WCRxQw
AAAECuXvUxDg2J8RvI6EoCFTBjjLrotdM94vQdVdEEUghqRyZ4ipNopWArePKqHgscCf/h
cXcv6YW7YW5IhvZYJHFDAAAABHRlc3QB
-----END OPENSSH PRIVATE KEY-----''';

/// The same shape a passphrase-protected key has: `aes256-ctr` keyed by
/// `bcrypt_pbkdf` at 24 rounds, which is what the ssh-keygen that wrote it
/// chose. The round count lives in the key, not in the format, which is why
/// the tests assert the number they do.
const _ed25519EncPem = '''
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABAg5Riwua
5beS4snWWUidONAAAAGAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIEDCcGtimUlgaIHj
G1FSAGBNXDjxJpZ4d+uUiVxL0N8oAAAAkDONlRPg/9bWYy0tjcW/wn00ojgtXOZUblfZHR
phdwU92jyvjO0h8UnsMsSXjJRGzdq/DdVbNTVoqgYAbCCK3hwrtJIj8c7j5T+l6KzhI7a3
FjyMnkPazhD4KqM6JIhL2ODTcXfue7n0u/gRKVYHjCRQEoxKqUGHs9AHgfp5LtKRkxUsN9
tnsPaek1tyG3JuTQ==
-----END OPENSSH PRIVATE KEY-----''';

const _encPassphrase = 'hunter2';

const _ecdsaPem = '''
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAaAAAABNlY2RzYS
1zaGEyLW5pc3RwMjU2AAAACG5pc3RwMjU2AAAAQQQc1TjnppHiTdGaj+xNnQh++l3GSBgB
6B4BlLnkJ10nCLhqi2pNOgRaOLtKNOLNJ5MAamrAVozurBrjnMYUp5mUAAAAoCz+zxAs/s
8QAAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBBzVOOemkeJN0ZqP
7E2dCH76XcZIGAHoHgGUueQnXScIuGqLak06BFo4u0o04s0nkwBqasBWjO6sGuOcxhSnmZ
QAAAAgP0rwW2WsQ8RYnxy27cil8AleViluaY3v0eI2eO9/aYwAAAAEdGVzdAECAwQ=
-----END OPENSSH PRIVATE KEY-----''';

final _message = Uint8List.fromList(List.generate(32, (i) => i * 7 & 0xff));

/// Answers the asymmetric operations from what the test handed it, and records
/// what it was asked for. `null` for an operation means "not implemented", so a
/// field left unset exercises the fallback.
class _AsymBackend extends SSHCryptoBackend {
  _AsymBackend({
    this.x25519Pair,
    this.shared,
    this.edSign,
    this.edVerify,
    this.ecSign,
    this.ecVerify,
    this.bcrypt,
  });

  final (Uint8List, Uint8List)? x25519Pair;
  final Uint8List? shared;
  final Uint8List? edSign;
  final bool? edVerify;
  final (BigInt, BigInt)? ecSign;
  final bool? ecVerify;
  final Uint8List? bcrypt;

  final calls = <String>[];

  @override
  (Uint8List, Uint8List)? x25519KeyPair() {
    calls.add('x25519KeyPair');
    return x25519Pair;
  }

  @override
  Uint8List? x25519SharedSecret(Uint8List privateKey, Uint8List peerPublic) {
    calls.add('x25519SharedSecret');
    return shared;
  }

  @override
  Uint8List? ed25519Sign(Uint8List privateKey, Uint8List message) {
    calls.add('ed25519Sign');
    return edSign;
  }

  @override
  bool? ed25519Verify(Uint8List pub, Uint8List message, Uint8List signature) {
    calls.add('ed25519Verify');
    return edVerify;
  }

  @override
  (BigInt, BigInt)? ecdsaSign(String curveId, BigInt d, Uint8List message) {
    calls.add('ecdsaSign:$curveId');
    return ecSign;
  }

  @override
  bool? ecdsaVerify(
    String curveId,
    Uint8List q,
    Uint8List message,
    BigInt r,
    BigInt s,
  ) {
    calls.add('ecdsaVerify:$curveId');
    return ecVerify;
  }

  @override
  Uint8List? bcryptPbkdf(
    Uint8List passphrase,
    Uint8List salt,
    int rounds,
    int outputLength,
  ) {
    calls.add('bcryptPbkdf:$rounds:$outputLength');
    return bcrypt;
  }
}

void _asymTests() {
  tearDown(() => sshCryptoBackend = null);

  group('a backend that implements nothing', () {
    // The whole reason the methods have defaults: `extends SSHCryptoBackend`
    // with no overrides has to behave exactly like no backend at all.
    test('changes none of it', () async {
      sshCryptoBackend = _AsymBackend();

      final kex = await SSHKexX25519.createAsync();
      final peer = await SSHKexX25519.createAsync();
      expect(kex.privateKey, hasLength(32));
      expect(
        await kex.computeSecretAsync(peer.publicKey),
        await peer.computeSecretAsync(kex.publicKey),
      );

      final pair = SSHKeyPair.fromPem(_ed25519Pem).first;
      final pub = pair.toPublicKey() as SSHEd25519PublicKey;
      expect(
        pub.verify(_message, pair.sign(_message) as SSHEd25519Signature),
        isTrue,
      );
      expect(
        SSHKeyPair.fromPem(_ed25519EncPem, _encPassphrase).first.type,
        'ssh-ed25519',
      );
    });
  });

  group('x25519', () {
    test('uses the backend keypair instead of the isolate', () async {
      final priv = Uint8List.fromList(List.filled(32, 7));
      final pub = Uint8List.fromList(List.filled(32, 9));
      final backend = _AsymBackend(x25519Pair: (priv, pub));
      sshCryptoBackend = backend;

      final kex = await SSHKexX25519.createAsync();
      expect(backend.calls, ['x25519KeyPair']);
      expect(kex.privateKey, priv);
      expect(kex.publicKey, pub);
    });

    // RFC 8731. The check has to be on the path every caller takes: a peer
    // sending a low-order point forces a secret it knows too, and TweetNaCl
    // returns the all-zero result without complaint.
    test('a low-order peer point is refused with or without a backend',
        () async {
      // All-zero is the canonical low-order point, and an all-zero secret is
      // how curve25519 reports one.
      for (final backend in [
        _AsymBackend(),
        _AsymBackend(shared: Uint8List(32)),
      ]) {
        sshCryptoBackend = backend;
        final kex = await SSHKexX25519.createAsync();
        expect(
          () => kex.computeSecretAsync(Uint8List(32)),
          throwsA(isA<SSHHandshakeError>()),
          reason: 'backend: ${backend.calls}',
        );
        expect(
          () => kex.computeSecret(Uint8List(32)),
          throwsA(isA<SSHHandshakeError>()),
        );
      }
    });

    test('a peer key of the wrong length fails the same way either way',
        () async {
      // The length check lives in `_ScalarMult`, which a backend does not go
      // through, so without one of its own the error would depend on which
      // backend happened to be installed.
      for (final backend in [
        _AsymBackend(),
        _AsymBackend(shared: Uint8List(32))
      ]) {
        sshCryptoBackend = backend;
        final kex = await SSHKexX25519.createAsync();
        expect(
          () => kex.computeSecretAsync(Uint8List(31)),
          throwsArgumentError,
        );
      }
    });

    test('uses the backend shared secret', () async {
      final secret = Uint8List.fromList(List.generate(32, (i) => i + 1));
      final backend = _AsymBackend(shared: secret);
      sshCryptoBackend = backend;

      final kex = await SSHKexX25519.createAsync();
      expect(
        await kex.computeSecretAsync(Uint8List(32)),
        decodeBigIntWithSign(1, secret),
      );
      expect(backend.calls, contains('x25519SharedSecret'));
    });
  });

  group('ed25519', () {
    test('signs with the backend when it offers one', () {
      final sig = Uint8List.fromList(List.generate(64, (i) => i));
      final backend = _AsymBackend(edSign: sig);
      sshCryptoBackend = backend;

      final pair = SSHKeyPair.fromPem(_ed25519Pem).first;
      expect((pair.sign(_message) as SSHEd25519Signature).signature, sig);
      expect(backend.calls, ['ed25519Sign']);
    });

    // The one that decides whether a forged host key is accepted: `false` is a
    // rejection and `null` is "ask the built-in", and reading either as the
    // other is the whole risk of this seam.
    test('false is a rejection and null is a fallback', () {
      final pair = SSHKeyPair.fromPem(_ed25519Pem).first;
      final pub = pair.toPublicKey() as SSHEd25519PublicKey;
      final good = pair.sign(_message) as SSHEd25519Signature;

      sshCryptoBackend = _AsymBackend(edVerify: false);
      expect(
        pub.verify(_message, good),
        isFalse,
        reason: 'a backend false must stand even for a valid signature',
      );

      sshCryptoBackend = _AsymBackend();
      expect(
        pub.verify(_message, good),
        isTrue,
        reason: 'null is unsupported, not invalid',
      );

      sshCryptoBackend = _AsymBackend(edVerify: true);
      expect(
        pub.verify(_message, good),
        isTrue,
        reason: 'a backend true is taken as given',
      );
    });

    // The two paths reject a bad signature differently, and the difference is
    // worth pinning down rather than smoothing over: pinenacl throws, while a
    // backend answers `false`. `SSHTransport._verifyHostkey`'s caller turns
    // `false` into `SSHHostkeyError`, so the backend path produces a typed SSH
    // error where the built-in leaks pinenacl's. Both refuse; neither returns
    // true.
    test('a tampered signature is refused either way', () {
      final pair = SSHKeyPair.fromPem(_ed25519Pem).first;
      final pub = pair.toPublicKey() as SSHEd25519PublicKey;
      final good = pair.sign(_message) as SSHEd25519Signature;
      final tampered = SSHEd25519Signature(
        Uint8List.fromList(good.signature)..[0] ^= 1,
      );

      sshCryptoBackend = _AsymBackend();
      expect(() => pub.verify(_message, tampered), throwsA(anything));

      sshCryptoBackend = _AsymBackend(edVerify: false);
      expect(pub.verify(_message, tampered), isFalse);
    });
  });

  group('ecdsa', () {
    late SSHKeyPair pair;
    late SSHEcdsaPublicKey pub;

    setUp(() {
      sshCryptoBackend = null;
      pair = SSHKeyPair.fromPem(_ecdsaPem).first;
      pub = pair.toPublicKey() as SSHEcdsaPublicKey;
    });

    test('signs with the backend, under the curve from the key', () {
      final rs = (BigInt.from(11), BigInt.from(22));
      final backend = _AsymBackend(ecSign: rs);
      sshCryptoBackend = backend;

      final sig = pair.sign(_message) as SSHEcdsaSignature;
      expect(backend.calls, ['ecdsaSign:nistp256']);
      expect((sig.r, sig.s), rs);
      expect(sig.type, 'ecdsa-sha2-nistp256');
    });

    test('falls back when the backend has no ecdsa', () {
      final backend = _AsymBackend();
      sshCryptoBackend = backend;

      final sig = pair.sign(_message) as SSHEcdsaSignature;
      expect(backend.calls, ['ecdsaSign:nistp256']);
      // Signed by pointycastle, so it must verify through pointycastle.
      sshCryptoBackend = null;
      expect(pub.verify(_message, sig), isTrue);
    });

    // The same three-valued contract the Ed25519 host key has, and the same
    // reason: this is what decides whether a forged host key is accepted.
    test('false is a rejection and null is a fallback', () {
      final good = pair.sign(_message) as SSHEcdsaSignature;

      final rejecting = _AsymBackend(ecVerify: false);
      sshCryptoBackend = rejecting;
      expect(
        pub.verify(_message, good),
        isFalse,
        reason: 'a backend false must stand even for a valid signature',
      );
      expect(rejecting.calls, ['ecdsaVerify:nistp256']);

      sshCryptoBackend = _AsymBackend();
      expect(
        pub.verify(_message, good),
        isTrue,
        reason: 'null is unsupported, not invalid',
      );

      sshCryptoBackend = _AsymBackend(ecVerify: true);
      expect(
        pub.verify(_message, good),
        isTrue,
        reason: 'a backend true is taken as given',
      );
    });

    test('the built-in still rejects a tampered signature', () {
      sshCryptoBackend = _AsymBackend();
      final good = pair.sign(_message) as SSHEcdsaSignature;
      final tampered = SSHEcdsaSignature(
        'ecdsa-sha2-nistp256',
        good.r + BigInt.one,
        good.s,
      );
      expect(pub.verify(_message, tampered), isFalse);
    });
  });

  group('bcrypt_pbkdf', () {
    test('is asked with the rounds and the length the key file implies', () {
      // 24 is the round count stored in this key, not a constant of the
      // format — asserting it is how a fixture regenerated with different
      // settings announces itself. 48 is aes256-ctr's 32-byte key plus its
      // 16-byte IV, cut from one derived buffer.
      final backend = _AsymBackend(bcrypt: Uint8List(48));
      sshCryptoBackend = backend;

      // The derived key is wrong, so opening it must fail — which is also the
      // proof that the backend's answer was the one used.
      expect(
        () => SSHKeyPair.fromPem(_ed25519EncPem, _encPassphrase),
        throwsA(isA<SSHKeyDecryptError>()),
      );
      expect(backend.calls, ['bcryptPbkdf:24:48']);
    });

    // What a real derivation produces, so a backend can hand back exactly
    // these bytes in an awkward shape and the key must still open.
    Uint8List derived() {
      final pass = Uint8List.fromList(_encPassphrase.codeUnits);
      final salt = _saltOf(_ed25519EncPem);
      final out = Uint8List(48);
      builtin.bcrypt_pbkdf(
        pass,
        pass.length,
        salt,
        salt.length,
        out,
        out.length,
        24,
      );
      return out;
    }

    // The silent one. Both callers cut the key and the IV out of the returned
    // list's *buffer* from offset zero, so a backend answering with a view into
    // a larger buffer would have them read from whatever precedes it — and the
    // only symptom is a correct passphrase that will not open the key.
    test('a backend view into a larger buffer is normalised', () {
      final padded = Uint8List(80)..setRange(16, 64, derived());
      sshCryptoBackend = _AsymBackend(
        bcrypt: Uint8List.view(padded.buffer, 16, 48),
      );
      expect(
        SSHKeyPair.fromPem(_ed25519EncPem, _encPassphrase).first.type,
        'ssh-ed25519',
      );
    });

    test('a backend of the wrong length is refused, not used', () {
      sshCryptoBackend = _AsymBackend(bcrypt: Uint8List(32));
      expect(
        () => SSHKeyPair.fromPem(_ed25519EncPem, _encPassphrase),
        throwsA(isA<StateError>()),
      );
    });

    test('falls back to the built-in when the backend has none', () {
      final backend = _AsymBackend();
      sshCryptoBackend = backend;
      expect(
        SSHKeyPair.fromPem(_ed25519EncPem, _encPassphrase).first.type,
        'ssh-ed25519',
      );
      expect(backend.calls, ['bcryptPbkdf:24:48']);
    });
  });
}

/// The `bcrypt` salt out of an OpenSSH private key's kdf options.
///
/// Read off the wire form rather than hard-coded beside the fixture, so the two
/// cannot drift apart.
Uint8List _saltOf(String pemText) {
  final pairs = OpenSSHKeyPairs.decode(SSHPem.decode(pemText).content);
  return (pairs.kdfOptions! as OpenSSHBcryptKdfOptions).salt;
}
