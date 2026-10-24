import 'dart:typed_data';

import 'package:dartssh2/src/hostkey/hostkey_ecdsa.dart';
import 'package:dartssh2/src/hostkey/hostkey_ed25519.dart';
import 'package:dartssh2/src/hostkey/hostkey_rsa.dart';
import 'package:dartssh2/src/message/base.dart';
import 'package:dartssh2/src/ssh_errors.dart';
import 'package:dartssh2/src/ssh_hostkey.dart';

/// An OpenSSH host certificate (PROTOCOL.certkeys): a host key, signed by a
/// certificate authority.
///
/// The exchange is signed by [publicKey], the key inside. [verify] checks
/// what holds whoever the authority is — that it is a host certificate, in
/// date, with nothing it does not understand, and signed by [signatureKey];
/// whether that authority is trusted is the caller's question, and without
/// one [publicKey] is trusted the way a plain host key is.
class SSHHostCertificate {
  static const _suffix = '-cert-v01@openssh.com';

  /// `SSH_CERT_TYPE_HOST`.
  static const hostType = 2;

  /// The certificate's own type, e.g. `ssh-ed25519-cert-v01@openssh.com`.
  final String type;

  /// The certified key, encoded as a plain host key (`ssh-ed25519`, `ssh-rsa`,
  /// `ecdsa-sha2-*`). Its fingerprint is the host's, as OpenSSH prints it.
  final Uint8List publicKey;

  final int serial;

  /// `SSH_CERT_TYPE_USER` (1) or `SSH_CERT_TYPE_HOST` (2).
  final int certType;

  final String keyId;

  final List<String> principals;

  /// Seconds since the epoch.
  final int validAfter;

  /// Seconds since the epoch; negative for "forever", which is all ones on the
  /// wire and past what a signed 64-bit integer holds.
  final int validBefore;

  /// Option names; a host certificate defines none.
  final List<String> criticalOptions;

  /// The authority's public key.
  final Uint8List signatureKey;

  final Uint8List signature;

  /// Everything [signature] covers: the certificate up to and including
  /// [signatureKey].
  final Uint8List signed;

  SSHHostCertificate._({
    required this.type,
    required this.publicKey,
    required this.serial,
    required this.certType,
    required this.keyId,
    required this.principals,
    required this.validAfter,
    required this.validBefore,
    required this.criticalOptions,
    required this.signatureKey,
    required this.signature,
    required this.signed,
  });

  /// Whether [encoded] starts with a certificate type.
  static bool isCertificate(Uint8List encoded) =>
      SSHHostKey.getType(encoded).endsWith(_suffix);

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
        key.writeUtf8(reader.readUtf8()); // curve
        key.writeString(reader.readString()); // Q
      default:
        throw SSHHostkeyError('Unsupported certificate type: $type');
    }

    final serial = reader.readUint64();
    final certType = reader.readUint32();
    final keyId = reader.readUtf8(allowMalformed: true);
    final principals = _strings(reader.readString());
    final validAfter = reader.readUint64();
    final validBefore = reader.readUint64();
    final criticalOptions = _optionNames(reader.readString());
    reader.readString(); // extensions
    reader.readString(); // reserved
    final signatureKey = reader.readString();
    final signedLength = reader.offset;
    final signature = reader.readString();

    return SSHHostCertificate._(
      type: type,
      publicKey: key.takeBytes(),
      serial: serial,
      certType: certType,
      keyId: keyId,
      principals: principals,
      validAfter: validAfter,
      validBefore: validBefore,
      criticalOptions: criticalOptions,
      signatureKey: signatureKey,
      signature: signature,
      signed: Uint8List.sublistView(data, 0, signedLength),
    );
  }

  /// Throws [SSHHostkeyError] saying why this certificate is not one a host
  /// may present at [now]. See the class for what is not checked here.
  void verify({DateTime? now}) {
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
    final seconds = (now ?? DateTime.now()).millisecondsSinceEpoch ~/ 1000;
    if (seconds < validAfter) {
      throw SSHHostkeyError('Host certificate is not yet valid');
    }
    if (validBefore >= 0 && seconds >= validBefore) {
      throw SSHHostkeyError('Host certificate has expired');
    }
    if (!_signedByAuthorityOrFalse()) {
      throw SSHHostkeyError('Host certificate signature is invalid');
    }
  }

  bool _signedByAuthorityOrFalse() {
    try {
      return _signedByAuthority();
    } on SSHHostkeyError {
      rethrow;
    } catch (_) {
      // pinenacl throws on a bad Ed25519 signature rather than answering no.
      return false;
    }
  }

  bool _signedByAuthority() {
    final keyType = SSHHostKey.getType(signatureKey);
    final signatureType = SSHSignature.getType(signature);
    switch (keyType) {
      case SSHEd25519PublicKey.type:
        return SSHEd25519PublicKey.decode(signatureKey)
            .verify(signed, SSHEd25519Signature.decode(signature));
      case SSHRsaPublicKey.type:
        // SHA-1 is refused, as OpenSSH refuses it for authorities by default
        // (`CASignatureAlgorithms`).
        if (signatureType != SSHRsaSignatureType.sha256 &&
            signatureType != SSHRsaSignatureType.sha512) {
          throw SSHHostkeyError(
            'Host certificate signed with refused algorithm $signatureType',
          );
        }
        return SSHRsaPublicKey.decode(signatureKey)
            .verify(signed, SSHRsaSignature.decode(signature));
      case 'ecdsa-sha2-nistp256':
      case 'ecdsa-sha2-nistp384':
      case 'ecdsa-sha2-nistp521':
        if (signatureType != keyType) {
          throw SSHHostkeyError(
            'Host certificate signature $signatureType does not match $keyType',
          );
        }
        return SSHEcdsaPublicKey.decode(signatureKey)
            .verify(signed, SSHEcdsaSignature.decode(signature));
      default:
        throw SSHHostkeyError('Unsupported certificate authority: $keyType');
    }
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
