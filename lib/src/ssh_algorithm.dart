import 'package:dartssh2/src/algorithm/ssh_cipher_type.dart';
import 'package:dartssh2/src/algorithm/ssh_hostkey_type.dart';
import 'package:dartssh2/src/algorithm/ssh_kex_type.dart';
import 'package:dartssh2/src/algorithm/ssh_mac_type.dart';
import 'package:dartssh2/src/algorithm/ssh_pubkey_type.dart';

abstract class SSHAlgorithm {
  String get name;

  const SSHAlgorithm();

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

  /// Signature algorithms offered for client `publickey` authentication.
  ///
  /// Defaults to modern algorithms only; SHA-1 `ssh-rsa` must be opted into
  /// explicitly for legacy daemons that predate RFC 8332.
  final List<SSHPubkeyType> pubkey;

  /// Algorithm used for the encryption.
  final List<SSHCipherType> cipher;

  /// Algorithm used for the authentication.
  final List<SSHMacType> mac;

  const SSHAlgorithms({
    // Legacy SHA-1 key exchanges remain available for callers that explicitly
    // opt into them, but are not advertised by default.
    this.kex = const [
      SSHKexType.x25519Rfc,
      SSHKexType.x25519,
      SSHKexType.nistp521,
      SSHKexType.nistp384,
      SSHKexType.nistp256,
      SSHKexType.dh16Sha512,
      SSHKexType.dh14Sha256,
      SSHKexType.dhGexSha256,
    ],
    // Each certificate just before the key it certifies. The certified key
    // is what is verified and pinned, so a server negotiates the same key it
    // did before it had a certificate — all certificates first would move a
    // host with a certificate for its RSA key only off its Ed25519 key, and
    // ask about a key it was never pinned on.
    this.hostkey = const [
      SSHHostkeyType.ed25519Cert,
      SSHHostkeyType.ed25519,
      SSHHostkeyType.ecdsa521Cert,
      SSHHostkeyType.ecdsa521,
      SSHHostkeyType.ecdsa384Cert,
      SSHHostkeyType.ecdsa384,
      SSHHostkeyType.ecdsa256Cert,
      SSHHostkeyType.ecdsa256,
      SSHHostkeyType.rsaSha512Cert,
      SSHHostkeyType.rsaSha512,
      SSHHostkeyType.rsaSha256Cert,
      SSHHostkeyType.rsaSha256,
    ],
    // RFC 8332 mandates `rsa-sha2-256` on compliant servers (`rsa-sha2-512`
    // remains optional), so only `rsa-sha2-256` is offered by default to avoid
    // doubling failed probes on embedded daemons with low `MaxAuthTries`.
    // Legacy SHA-1 `ssh-rsa` is opt-in only.
    this.pubkey = const [
      SSHPubkeyType.ed25519Cert,
      SSHPubkeyType.ed25519,
      SSHPubkeyType.skEd25519Cert,
      SSHPubkeyType.skEd25519,
      SSHPubkeyType.ecdsa521Cert,
      SSHPubkeyType.ecdsa521,
      SSHPubkeyType.ecdsa384Cert,
      SSHPubkeyType.ecdsa384,
      SSHPubkeyType.ecdsa256Cert,
      SSHPubkeyType.ecdsa256,
      SSHPubkeyType.skEcdsa256Cert,
      SSHPubkeyType.skEcdsa256,
      SSHPubkeyType.rsaSha256Cert,
      SSHPubkeyType.rsaSha256,
    ],

    /// CTR first for the widest interoperability, then ChaCha20-Poly1305,
    /// then AES-GCM. ChaCha20-Poly1305 ranks above GCM because pointycastle's
    /// GHASH is roughly 30x slower than its ChaCha20 — on a server that
    /// permits only AEAD ciphers, the order between these two decides whether
    /// the connection runs at ~50 MiB/s or ~2 MiB/s. CBC remains a legacy
    /// available only through explicit configuration.
    this.cipher = const [
      // Prioritise widely-supported CTR modes for compatibility
      SSHCipherType.aes256ctr,
      SSHCipherType.aes128ctr,
      // Fast AEAD first; GCM only when the peer offers nothing better
      SSHCipherType.chacha20poly1305,
      SSHCipherType.aes256gcm,
      SSHCipherType.aes128gcm,
    ],
    // SHA-1, MD5, and truncated MACs remain opt-in for legacy peers.
    this.mac = const [
      SSHMacType.hmacSha256Etm,
      SSHMacType.hmacSha512Etm,
      SSHMacType.hmacSha256,
      SSHMacType.hmacSha512,
    ],
  });
}
