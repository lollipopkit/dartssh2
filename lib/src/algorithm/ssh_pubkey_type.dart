import 'package:dartssh2/src/ssh_algorithm.dart';

/// Public-key signature algorithms offered during client `publickey`
/// authentication (OpenSSH `PubkeyAcceptedAlgorithms`).
///
/// Separate from [SSHHostkeyType] because FIDO2 security-key algorithms
/// (`sk-*`) are client userauth algorithms rather than server host-key
/// algorithms.
class SSHPubkeyType extends SSHAlgorithm {
  static const rsaSha1 = SSHPubkeyType._('ssh-rsa');
  static const rsaSha256 = SSHPubkeyType._('rsa-sha2-256');
  static const rsaSha512 = SSHPubkeyType._('rsa-sha2-512');
  static const ecdsa256 = SSHPubkeyType._('ecdsa-sha2-nistp256');
  static const ecdsa384 = SSHPubkeyType._('ecdsa-sha2-nistp384');
  static const ecdsa521 = SSHPubkeyType._('ecdsa-sha2-nistp521');
  static const ed25519 = SSHPubkeyType._('ssh-ed25519');
  static const skEd25519 = SSHPubkeyType._('sk-ssh-ed25519@openssh.com');
  static const skEcdsa256 =
      SSHPubkeyType._('sk-ecdsa-sha2-nistp256@openssh.com');

  static const rsaSha1Cert =
      SSHPubkeyType._('ssh-rsa-cert-v01@openssh.com', rsaSha1);
  static const rsaSha256Cert =
      SSHPubkeyType._('rsa-sha2-256-cert-v01@openssh.com', rsaSha256);
  static const rsaSha512Cert =
      SSHPubkeyType._('rsa-sha2-512-cert-v01@openssh.com', rsaSha512);
  static const ecdsa256Cert =
      SSHPubkeyType._('ecdsa-sha2-nistp256-cert-v01@openssh.com', ecdsa256);
  static const ecdsa384Cert =
      SSHPubkeyType._('ecdsa-sha2-nistp384-cert-v01@openssh.com', ecdsa384);
  static const ecdsa521Cert =
      SSHPubkeyType._('ecdsa-sha2-nistp521-cert-v01@openssh.com', ecdsa521);
  static const ed25519Cert =
      SSHPubkeyType._('ssh-ed25519-cert-v01@openssh.com', ed25519);
  static const skEd25519Cert =
      SSHPubkeyType._('sk-ssh-ed25519-cert-v01@openssh.com', skEd25519);
  static const skEcdsa256Cert = SSHPubkeyType._(
    'sk-ecdsa-sha2-nistp256-cert-v01@openssh.com',
    skEcdsa256,
  );

  const SSHPubkeyType._(this.name, [this.certified]);

  @override
  final String name;

  /// For a certificate, the algorithm of the key it certifies; null otherwise.
  final SSHPubkeyType? certified;

  bool get isCertificate => certified != null;

  SSHPubkeyType get keyType => certified ?? this;
}
