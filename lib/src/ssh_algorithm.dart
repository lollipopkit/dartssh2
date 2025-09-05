import 'package:dartssh2/src/algorithm/ssh_cipher_type.dart';
import 'package:dartssh2/src/algorithm/ssh_compression_type.dart';
import 'package:dartssh2/src/algorithm/ssh_hostkey_type.dart';
import 'package:dartssh2/src/algorithm/ssh_kex_type.dart';
import 'package:dartssh2/src/algorithm/ssh_mac_type.dart';

mixin SSHAlgorithm {
  String get name;

  // RFC 4251: algorithm identifiers MUST be printable US-ASCII,
  // non-empty strings no longer than 64 characters
  bool get isValidAlgorithmName {
    if (name.isEmpty || name.length > 64) return false;

    // Check for printable US-ASCII (32-126, excluding DEL 127)
    for (int i = 0; i < name.length; i++) {
      int code = name.codeUnitAt(i);
      if (code <= 32 || code >= 127) return false;
    }

    // RFC 4251: Names MUST NOT contain comma, whitespace, control characters
    if (name.contains(',') || name.contains(' ') || name.contains('\t')) {
      return false;
    }

    // Check @ format rule
    final atIndex = name.indexOf('@');
    if (atIndex != -1) {
      // Must have only a single @ sign
      if (name.indexOf('@', atIndex + 1) != -1) return false;

      // Part after @ must be valid domain name
      final domain = name.substring(atIndex + 1);
      if (!_isValidDomainName(domain)) return false;
    }

    return true;
  }

  bool _isValidDomainName(String domain) {
    // Basic domain name validation
    if (domain.isEmpty) return false;
    final parts = domain.split('.');
    if (parts.length < 2) return false;

    for (final part in parts) {
      if (part.isEmpty) return false;
      if (!RegExp(r'^[a-zA-Z0-9-]+$').hasMatch(part)) return false;
      if (part.startsWith('-') || part.endsWith('-')) return false;
    }

    return true;
  }

  @override
  String toString() {
    assert(isValidAlgorithmName, 'Invalid algorithm name: $name');
    return '$runtimeType($name)';
  }
}

extension SSHAlgorithmList<T extends SSHAlgorithm> on List<T> {
  List<String> toNameList() {
    return map((algorithm) => algorithm.name).toList();
  }

  T? getByName(String name) {
    for (var algorithm in this) {
      if (algorithm.name == name) {
        return algorithm;
      }
    }
    return null;
  }
}

class SSHAlgorithms {
  /// Algorithm used for the key exchange.
  final List<SSHKexType> kex;

  /// Algorithm used for the host key.
  final List<SSHHostkeyType> hostkey;

  /// Algorithm used for the encryption.
  final List<SSHCipherType> cipher;

  /// Algorithm used for the authentication.
  final List<SSHMacType> mac;

  /// Algorithm used for compression.
  final List<SSHCompressionType> compression;

  const SSHAlgorithms({
    this.kex = const [
      SSHKexType.x25519,
      SSHKexType.nistp521,
      SSHKexType.nistp384,
      SSHKexType.nistp256,
      SSHKexType.dhGexSha256,
      SSHKexType.dh16Sha512,
      SSHKexType.dh14Sha256,
      SSHKexType.dh14Sha1,
      SSHKexType.dhGexSha1,
      SSHKexType.dh1Sha1,
    ],
    this.hostkey = const [
      SSHHostkeyType.ed25519,
      SSHHostkeyType.rsaSha512,
      SSHHostkeyType.rsaSha256,
      SSHHostkeyType.rsaSha1,
      SSHHostkeyType.ecdsa521,
      SSHHostkeyType.ecdsa384,
      SSHHostkeyType.ecdsa256,
    ],

    /// Keep this sequence for safety.
    this.cipher = const [
      SSHCipherType.aes256ctr,
      SSHCipherType.aes128ctr,
      SSHCipherType.aes256cbc,
      SSHCipherType.aes128cbc,
    ],
    this.mac = const [
      SSHMacType.hmacSha1,
      SSHMacType.hmacSha256,
      SSHMacType.hmacSha512,
      SSHMacType.hmacMd5,
    ],
    this.compression = const [
      SSHCompressionType.zlib,
      SSHCompressionType.none,
    ],
  });
}
