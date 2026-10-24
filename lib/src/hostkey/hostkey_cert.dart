import 'dart:typed_data';

import 'package:dartssh2/src/hostkey/hostkey_ed25519.dart';
import 'package:dartssh2/src/hostkey/hostkey_rsa.dart';
import 'package:dartssh2/src/message/base.dart';
import 'package:dartssh2/src/ssh_errors.dart';

/// An OpenSSH host certificate (PROTOCOL.certkeys): a host key, signed by a
/// certificate authority.
///
/// Only the certified key is read. With no authority trusted, OpenSSH does
/// the same — "No matching CA found. Retry with plain key" — and checks
/// nothing else about the certificate: anyone can sign one, so its dates, its
/// options and its signature say nothing until an authority is trusted, and
/// refusing over them would only turn away a host whose key is fine.
class SSHHostCertificate {
  static const _suffix = '-cert-v01@openssh.com';

  /// The certificate's own type, e.g. `ssh-ed25519-cert-v01@openssh.com`.
  final String type;

  /// The certified key, encoded as a plain host key (`ssh-ed25519`, `ssh-rsa`,
  /// `ecdsa-sha2-*`). Its fingerprint is the host's, as OpenSSH prints it.
  final Uint8List publicKey;

  SSHHostCertificate._(this.type, this.publicKey);

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
    return SSHHostCertificate._(type, key.takeBytes());
  }
}
