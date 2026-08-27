import 'dart:typed_data';

import 'package:dartssh2/src/algorithm/ssh_crypto_backend.dart';
import 'package:dartssh2/src/ssh_algorithm.dart';
import 'package:pointycastle/export.dart';

import '../utils/truncated_hmac.dart';

class SSHMacType extends SSHAlgorithm {
  static const hmacMd5 = SSHMacType._(
    name: 'hmac-md5',
    hmacName: 'hmac-md5',
    keySize: 16,
    macSize: 16,
    macFactory: _hmacMd5Factory,
  );

  static const hmacSha1 = SSHMacType._(
    name: 'hmac-sha1',
    hmacName: 'hmac-sha1',
    keySize: 20,
    macSize: 20,
    macFactory: _hmacSha1Factory,
  );

  static const hmacSha256 = SSHMacType._(
    name: 'hmac-sha2-256',
    hmacName: 'hmac-sha2-256',
    keySize: 32,
    macSize: 32,
    macFactory: _hmacSha256Factory,
  );

  static const hmacSha512 = SSHMacType._(
    name: 'hmac-sha2-512',
    hmacName: 'hmac-sha2-512',
    keySize: 64,
    macSize: 64,
    macFactory: _hmacSha512Factory,
  );

  // Non-standard MAC: RFC 6668/IANA only standardizes hmac-sha2-256 and hmac-sha2-512.
  // These use custom names and are not IANA-registered.
  static const hmacSha256_96 = SSHMacType._(
    name: 'hmac-sha2-256-96',
    hmacName: 'hmac-sha2-256',
    keySize: 32,
    macSize: 12,
    macFactory: _hmacSha256_96Factory,
  );

  static const hmacSha512_96 = SSHMacType._(
    name: 'hmac-sha2-512-96',
    hmacName: 'hmac-sha2-512',
    keySize: 64,
    macSize: 12,
    macFactory: _hmacSha512_96Factory,
  );

  static const hmacSha256Etm = SSHMacType._(
    name: 'hmac-sha2-256-etm@openssh.com',
    hmacName: 'hmac-sha2-256',
    keySize: 32,
    macSize: 32,
    macFactory: _hmacSha256Factory,
    isEtm: true,
  );

  static const hmacSha512Etm = SSHMacType._(
    name: 'hmac-sha2-512-etm@openssh.com',
    hmacName: 'hmac-sha2-512',
    keySize: 64,
    macSize: 64,
    macFactory: _hmacSha512Factory,
    isEtm: true,
  );

  const SSHMacType._({
    required this.name,
    required this.hmacName,
    required this.keySize,
    required this.macSize,
    required this.macFactory,
    this.isEtm = false,
  });

  @override
  final String name;

  /// The underlying HMAC, with the `-etm@openssh.com` and `-96` suffixes gone.
  ///
  /// Neither changes how the tag is computed — encrypt-then-MAC changes what is
  /// fed in, and `-96` truncates the result — so several [name]s share one of
  /// these. It is what an [SSHCryptoBackend] is asked for.
  final String hmacName;

  final int keySize;

  /// The tag length in bytes, after truncation.
  final int macSize;

  final Mac Function() macFactory;

  /// Whether this MAC algorithm is an ETM (Encrypt-Then-MAC) variant.
  final bool isEtm;

  Mac createMac(Uint8List key) {
    if (key.length != keySize) {
      throw ArgumentError.value(key, 'key', 'Key must be $keySize bytes long');
    }

    // After the length check, so a backend is never handed something this
    // would have refused, and before the factory, so nothing is built twice.
    final native = sshCryptoBackend?.createMac(hmacName, key, macSize);
    if (native != null) return native;

    final mac = macFactory();
    mac.init(KeyParameter(key));
    return mac;
  }
}

Mac _hmacMd5Factory() {
  return HMac(MD5Digest(), 64);
}

Mac _hmacSha1Factory() {
  return HMac(SHA1Digest(), 64);
}

Mac _hmacSha256Factory() {
  return HMac(SHA256Digest(), 64);
}

Mac _hmacSha512Factory() {
  return HMac(SHA512Digest(), 128);
}

Mac _hmacSha256_96Factory() {
  return TruncatedHMac(SHA256Digest(), 64, 12);
}

Mac _hmacSha512_96Factory() {
  return TruncatedHMac(SHA512Digest(), 128, 12);
}
