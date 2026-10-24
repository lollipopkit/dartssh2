import 'dart:typed_data';

import 'package:dartssh2/src/hostkey/hostkey_ecdsa.dart';
import 'package:dartssh2/src/hostkey/hostkey_ed25519.dart';
import 'package:dartssh2/src/hostkey/hostkey_rsa.dart';
import 'package:dartssh2/src/message/base.dart';
import 'package:dartssh2/src/ssh_errors.dart';
import 'package:dartssh2/src/ssh_hostkey.dart';

/// The certificate authorities trusted to vouch for one host, and the names
/// it goes by — OpenSSH's `@cert-authority` lines that match it.
class SSHHostCertificateTrust {
  /// Public keys of the authorities, SSH-encoded (`ssh-ed25519`, `ssh-rsa`,
  /// `ecdsa-sha2-*`).
  final List<Uint8List> authorities;

  /// Names the host is reached by. A certificate signed by one of
  /// [authorities] must list one of them among its principals, unless it
  /// lists none.
  final List<String> principals;

  const SSHHostCertificateTrust({
    required this.authorities,
    required this.principals,
  });

  bool trusts(Uint8List authority) => authorities.any(
        (key) => _bytesEqual(key, authority),
      );
}

/// An OpenSSH host certificate (PROTOCOL.certkeys): a host key, signed by a
/// certificate authority.
///
/// With no authority trusted for the host, only [publicKey] matters: OpenSSH
/// says "No matching CA found. Retry with plain key" and checks nothing else,
/// since anyone can sign a certificate. Signed by a trusted one, [verify]
/// decides, and a certificate it refuses refuses the host — OpenSSH fails the
/// connection there too.
///
/// Everything after the certified key is read only when asked for, so a
/// certificate whose tail no authority will ever look at cannot turn a host
/// away.
class SSHHostCertificate {
  static const _suffix = '-cert-v01@openssh.com';

  /// `SSH_CERT_TYPE_HOST`.
  static const hostType = 2;

  /// The certificate's own type, e.g. `ssh-ed25519-cert-v01@openssh.com`.
  final String type;

  /// The certified key, encoded as a plain host key (`ssh-ed25519`, `ssh-rsa`,
  /// `ecdsa-sha2-*`). Its fingerprint is the host's, as OpenSSH prints it.
  final Uint8List publicKey;

  final Uint8List _data;

  /// Where the fields after the certified key start in [_data].
  final int _rest;

  SSHHostCertificate._(this.type, this.publicKey, this._data, this._rest);

  factory SSHHostCertificate.decode(Uint8List data) {
    final reader = SSHMessageReader(data);
    final type = reader.readUtf8();
    if (!type.endsWith(_suffix)) {
      throw SSHHostkeyError('Not a host certificate: $type');
    }
    final keyType = type.substring(0, type.length - _suffix.length);
    reader.readString(); // nonce

    final key = SSHMessageWriter()..writeUtf8(keyType);
    switch (keyType) {
      case SSHEd25519PublicKey.type:
        key.writeString(reader.readString());
      case SSHRsaPublicKey.type:
        key.writeMpint(reader.readMpint()); // e
        key.writeMpint(reader.readMpint()); // n
      case 'ecdsa-sha2-nistp256':
      case 'ecdsa-sha2-nistp384':
      case 'ecdsa-sha2-nistp521':
        final curve = reader.readUtf8();
        if (keyType != 'ecdsa-sha2-$curve') {
          throw SSHHostkeyError(
              'Certificate curve $curve does not match $type');
        }
        key.writeUtf8(curve);
        key.writeString(reader.readString()); // Q
      default:
        throw SSHHostkeyError('Unsupported certificate type: $type');
    }
    return SSHHostCertificate._(type, key.takeBytes(), data, reader.offset);
  }

  late final _CertificateFields _fields = () {
    try {
      return _CertificateFields.read(_data, _rest);
    } catch (e) {
      throw SSHHostkeyError('Malformed host certificate: $e');
    }
  }();

  /// `SSH_CERT_TYPE_USER` (1) or `SSH_CERT_TYPE_HOST` (2).
  int get certType => _fields.certType;

  String get keyId => _fields.keyId;

  /// Host names, which may hold `*` and `?` wildcards; none is any host.
  List<String> get principals => _fields.principals;

  /// Seconds since the epoch. Unsigned 64-bit on the wire, so [BigInt]: an
  /// `int` wraps at 2^63, and "forever" is all ones.
  BigInt get validAfter => _fields.validAfter;
  BigInt get validBefore => _fields.validBefore;

  /// Option names; a host certificate defines none.
  List<String> get criticalOptions => _fields.criticalOptions;

  /// The authority's public key.
  Uint8List get signatureKey => _fields.signatureKey;

  Uint8List get signature => _fields.signature;

  /// Everything [signature] covers: the certificate up to and including
  /// [signatureKey].
  Uint8List get signed => Uint8List.sublistView(_data, 0, _fields.signedLength);

  /// Throws [SSHHostkeyError] saying why a host reached as one of
  /// [principals] may not present this certificate at [now], for a caller
  /// that trusts its [signatureKey].
  void verify({required List<String> principals, DateTime? now}) {
    if (certType != hostType) {
      throw SSHHostkeyError(
          'Host presented a non-host certificate ($certType)');
    }
    if (criticalOptions.isNotEmpty) {
      throw SSHHostkeyError(
        'Host certificate has unsupported critical options: '
        '${criticalOptions.join(', ')}',
      );
    }
    final seconds =
        BigInt.from((now ?? DateTime.now()).millisecondsSinceEpoch ~/ 1000);
    if (seconds < validAfter) {
      throw SSHHostkeyError('Host certificate is not yet valid');
    }
    if (seconds >= validBefore) {
      throw SSHHostkeyError('Host certificate has expired');
    }
    // No principals is any host, and a principal may be a wildcard, as
    // OpenSSH reads both for a host certificate.
    if (this.principals.isNotEmpty &&
        !principals.any((name) => this.principals.any((p) => _glob(p, name)))) {
      throw SSHHostkeyError(
        'Host certificate is not valid for ${principals.join(', ')}: '
        'it names ${this.principals.join(', ')}',
      );
    }
    if (!_signedByAuthority()) {
      throw SSHHostkeyError('Host certificate signature is invalid');
    }
  }

  bool _signedByAuthority() {
    final keyType = SSHHostKey.getType(signatureKey);
    final signatureType = SSHSignature.getType(signature);
    // Decoded here, outside [_checks]: a malformed authority key or signature
    // is said as such, not as a signature that did not verify.
    switch (keyType) {
      case SSHEd25519PublicKey.type:
        final key = SSHEd25519PublicKey.decode(signatureKey);
        final sig = SSHEd25519Signature.decode(signature);
        return _checks(() => key.verify(signed, sig));
      case SSHRsaPublicKey.type:
        // SHA-1 is refused, as OpenSSH refuses it for authorities by default
        // (`CASignatureAlgorithms`).
        if (signatureType != SSHRsaSignatureType.sha256 &&
            signatureType != SSHRsaSignatureType.sha512) {
          throw SSHHostkeyError(
            'Host certificate signed with refused algorithm $signatureType',
          );
        }
        final key = SSHRsaPublicKey.decode(signatureKey);
        final sig = SSHRsaSignature.decode(signature);
        return _checks(() => key.verify(signed, sig));
      case 'ecdsa-sha2-nistp256':
      case 'ecdsa-sha2-nistp384':
      case 'ecdsa-sha2-nistp521':
        if (signatureType != keyType) {
          throw SSHHostkeyError(
            'Host certificate signature $signatureType does not match $keyType',
          );
        }
        final key = SSHEcdsaPublicKey.decode(signatureKey);
        final sig = SSHEcdsaSignature.decode(signature);
        return _checks(() => key.verify(signed, sig));
      default:
        throw SSHHostkeyError('Unsupported certificate authority: $keyType');
    }
  }

  /// [verify] as a yes or no: pinenacl throws on a bad Ed25519 signature
  /// rather than answering no.
  static bool _checks(bool Function() verify) {
    try {
      return verify();
    } catch (_) {
      return false;
    }
  }
}

/// The fields of a certificate after its certified key.
class _CertificateFields {
  final int certType;
  final String keyId;
  final List<String> principals;
  final BigInt validAfter;
  final BigInt validBefore;
  final List<String> criticalOptions;
  final Uint8List signatureKey;
  final int signedLength;
  final Uint8List signature;

  _CertificateFields._({
    required this.certType,
    required this.keyId,
    required this.principals,
    required this.validAfter,
    required this.validBefore,
    required this.criticalOptions,
    required this.signatureKey,
    required this.signedLength,
    required this.signature,
  });

  factory _CertificateFields.read(Uint8List data, int offset) {
    final reader = SSHMessageReader(data)..skip(offset);
    reader.readUint64(); // serial
    final certType = reader.readUint32();
    final keyId = reader.readUtf8(allowMalformed: true);
    final principals = _strings(reader.readString());
    final validAfter = _readUint64(reader);
    final validBefore = _readUint64(reader);
    final criticalOptions = _optionNames(reader.readString());
    reader.readString(); // extensions
    reader.readString(); // reserved
    final signatureKey = reader.readString();
    final signedLength = reader.offset;
    final signature = reader.readString();
    return _CertificateFields._(
      certType: certType,
      keyId: keyId,
      principals: principals,
      validAfter: validAfter,
      validBefore: validBefore,
      criticalOptions: criticalOptions,
      signatureKey: signatureKey,
      signedLength: signedLength,
      signature: signature,
    );
  }

  static BigInt _readUint64(SSHMessageReader reader) {
    final high = reader.readUint32();
    final low = reader.readUint32();
    return (BigInt.from(high) << 32) | BigInt.from(low);
  }

  static List<String> _strings(Uint8List data) {
    final reader = SSHMessageReader(data);
    return [for (; !reader.isDone;) reader.readUtf8(allowMalformed: true)];
  }

  /// Names of a `critical options` field: name/data pairs.
  static List<String> _optionNames(Uint8List data) {
    final reader = SSHMessageReader(data);
    final names = <String>[];
    while (!reader.isDone) {
      names.add(reader.readUtf8(allowMalformed: true));
      reader.readString();
    }
    return names;
  }
}

/// OpenSSH's `match_pattern`: `*` is any run of characters, `?` any one.
bool _glob(String pattern, String text) {
  var p = 0, t = 0, star = -1, mark = 0;
  while (t < text.length) {
    if (p < pattern.length && (pattern[p] == '?' || pattern[p] == text[t])) {
      p++;
      t++;
    } else if (p < pattern.length && pattern[p] == '*') {
      star = p++;
      mark = t;
    } else if (star != -1) {
      p = star + 1;
      t = ++mark;
    } else {
      return false;
    }
  }
  while (p < pattern.length && pattern[p] == '*') {
    p++;
  }
  return p == pattern.length;
}

bool _bytesEqual(Uint8List a, Uint8List b) {
  if (a.length != b.length) return false;
  for (var i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}
