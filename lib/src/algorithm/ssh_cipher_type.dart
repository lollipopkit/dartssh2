import 'dart:typed_data';

import 'package:dartssh2/src/ssh_algorithm.dart';
import 'package:dartssh2/src/algorithm/chacha20_poly1305.dart';
import 'package:pointycastle/export.dart';

class SSHCipherType with SSHAlgorithm {
  static const values = [
    tdescbc,
    aes128cbc,
    aes192cbc,
    aes256cbc,
    aes128ctr,
    aes192ctr,
    aes256ctr,
    aes128gcm,
    aes256gcm,
    chacha20poly1305,
  ];

  static const tdescbc = SSHCipherType._(
    name: '3des-cbc',
    keySize: 24,
    cipherFactory: _tdesCbcFactory,
    blockSizeOverride: 8,
    ivSizeOverride: 8,
  );

  static const aes128ctr = SSHCipherType._(
    name: 'aes128-ctr',
    keySize: 16,
    cipherFactory: _aesCtrFactory,
  );

  static const aes192ctr = SSHCipherType._(
    name: 'aes192-ctr',
    keySize: 24,
    cipherFactory: _aesCtrFactory,
  );

  static const aes256ctr = SSHCipherType._(
    name: 'aes256-ctr',
    keySize: 32,
    cipherFactory: _aesCtrFactory,
  );

  static const aes128cbc = SSHCipherType._(
    name: 'aes128-cbc',
    keySize: 16,
    cipherFactory: _aesCbcFactory,
  );

  static const aes192cbc = SSHCipherType._(
    name: 'aes192-cbc',
    keySize: 24,
    cipherFactory: _aesCbcFactory,
  );

  static const aes256cbc = SSHCipherType._(
    name: 'aes256-cbc',
    keySize: 32,
    cipherFactory: _aesCbcFactory,
  );

  static const aes128gcm = SSHCipherType._(
    name: 'aes128-gcm@openssh.com',
    keySize: 16,
    cipherFactory: _aesGcmFactory,
    isAEAD: true,
    tagSize: 16,
  );

  static const aes256gcm = SSHCipherType._(
    name: 'aes256-gcm@openssh.com',
    keySize: 32,
    cipherFactory: _aesGcmFactory,
    isAEAD: true,
    tagSize: 16,
  );

  static const chacha20poly1305 = SSHCipherType._(
    name: 'chacha20-poly1305@openssh.com',
    keySize: 64, // 32 bytes for ChaCha20 key + 32 bytes for Poly1305 key
    cipherFactory: _chacha20Poly1305Factory,
    isAEAD: true,
    tagSize: 16,
  );

  static SSHCipherType? fromName(String name) {
    for (final value in values) {
      if (value.name == name) {
        return value;
      }
    }
    return null;
  }

  const SSHCipherType._({
    required this.name,
    required this.keySize,
    required this.cipherFactory,
    this.isAEAD = false,
    this.tagSize = 0,
    this.blockSizeOverride,
    this.ivSizeOverride,
  });

  /// The name of the algorithm. For example, `"aes256-ctr`"`.
  @override
  final String name;

  final int keySize;

  final int? blockSizeOverride;
  final int? ivSizeOverride;

  int get ivSize => ivSizeOverride ?? 16;

  int get blockSize => blockSizeOverride ?? 16;

  /// Whether this is an AEAD cipher mode
  final bool isAEAD;

  /// Authentication tag size for AEAD modes
  final int tagSize;

  final dynamic Function() cipherFactory;

  /// Creates cipher for non-AEAD modes
  BlockCipher createCipher(
    Uint8List key,
    Uint8List iv, {
    required bool forEncryption,
  }) {
    if (isAEAD) {
      throw StateError('Use createAEADCipher for AEAD modes');
    }

    if (key.length != keySize) {
      throw ArgumentError.value(key, 'key', 'Key must be $keySize bytes long');
    }

    if (iv.length != ivSize) {
      throw ArgumentError.value(iv, 'iv', 'IV must be $ivSize bytes long');
    }

    final cipher = cipherFactory() as BlockCipher;
    cipher.init(forEncryption, ParametersWithIV(KeyParameter(key), iv));
    return cipher;
  }

  /// Creates cipher for AEAD modes
  AEADBlockCipher createAEADCipher(
    Uint8List key,
    Uint8List nonce, {
    required bool forEncryption,
    Uint8List? aad,
  }) {
    if (!isAEAD) {
      throw StateError('Use createCipher for non-AEAD modes');
    }

    if (key.length != keySize) {
      throw ArgumentError.value(key, 'key', 'Key must be $keySize bytes long');
    }

    final cipher = cipherFactory() as AEADBlockCipher;
    final params = AEADParameters(
      KeyParameter(key),
      tagSize * 8, // tagSize in bits
      nonce,
      aad ?? Uint8List(0),
    );
    cipher.init(forEncryption, params);
    return cipher;
  }
}

BlockCipher _aesCtrFactory() {
  final aes = AESEngine();
  return CTRBlockCipher(aes.blockSize, CTRStreamCipher(aes));
}

BlockCipher _aesCbcFactory() {
  return CBCBlockCipher(AESEngine());
}

BlockCipher _tdesCbcFactory() {
  return CBCBlockCipher(DESedeEngine());
}

/// Creates AES-GCM cipher factory
AEADBlockCipher _aesGcmFactory() {
  return GCMBlockCipher(AESEngine());
}

/// Creates ChaCha20-Poly1305 cipher factory
AEADBlockCipher _chacha20Poly1305Factory() {
  return SSHChaCha20Poly1305();
}
