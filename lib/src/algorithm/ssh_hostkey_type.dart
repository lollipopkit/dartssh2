import 'package:dartssh2/src/ssh_algorithm.dart';

class SSHHostkeyType extends SSHAlgorithm {
  static const rsaSha1 = SSHHostkeyType._('ssh-rsa');
  static const rsaSha256 = SSHHostkeyType._('rsa-sha2-256');
  static const rsaSha512 = SSHHostkeyType._('rsa-sha2-512');
  static const ecdsa256 = SSHHostkeyType._('ecdsa-sha2-nistp256');
  static const ecdsa384 = SSHHostkeyType._('ecdsa-sha2-nistp384');
  static const ecdsa521 = SSHHostkeyType._('ecdsa-sha2-nistp521');
  static const ed25519 = SSHHostkeyType._('ssh-ed25519');

  /// OpenSSH host certificates (PROTOCOL.certkeys): the host key, signed by a
  /// certificate authority. The key inside is what signs the exchange.
  static const rsaSha1Cert =
      SSHHostkeyType._('ssh-rsa-cert-v01@openssh.com', rsaSha1);
  static const rsaSha256Cert =
      SSHHostkeyType._('rsa-sha2-256-cert-v01@openssh.com', rsaSha256);
  static const rsaSha512Cert =
      SSHHostkeyType._('rsa-sha2-512-cert-v01@openssh.com', rsaSha512);
  static const ecdsa256Cert =
      SSHHostkeyType._('ecdsa-sha2-nistp256-cert-v01@openssh.com', ecdsa256);
  static const ecdsa384Cert =
      SSHHostkeyType._('ecdsa-sha2-nistp384-cert-v01@openssh.com', ecdsa384);
  static const ecdsa521Cert =
      SSHHostkeyType._('ecdsa-sha2-nistp521-cert-v01@openssh.com', ecdsa521);
  static const ed25519Cert =
      SSHHostkeyType._('ssh-ed25519-cert-v01@openssh.com', ed25519);

  const SSHHostkeyType._(this.name, [this.certified]);

  /// The name of the algorithm. For example, `"ssh-rsa`"`.
  @override
  final String name;

  /// For a certificate, the algorithm of the key it certifies; null otherwise.
  final SSHHostkeyType? certified;

  bool get isCertificate => certified != null;

  /// The algorithm the exchange is signed with: the certified key's for a
  /// certificate, this one otherwise.
  SSHHostkeyType get keyType => certified ?? this;
}
