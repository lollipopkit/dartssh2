import 'package:dartssh2/src/ssh_algorithm.dart';
import 'package:pointycastle/export.dart';

class SSHKexType with SSHAlgorithm {
  static const x25519 = SSHKexType._(
    name: 'curve25519-sha256@libssh.org',
    digestFactory: SHA256Digest.new,
  );

  static const nistp256 = SSHKexType._(
    name: 'ecdh-sha2-nistp256',
    digestFactory: SHA256Digest.new,
  );

  static const nistp384 = SSHKexType._(
    name: 'ecdh-sha2-nistp384',
    digestFactory: SHA384Digest.new,
  );

  static const nistp521 = SSHKexType._(
    name: 'ecdh-sha2-nistp521',
    digestFactory: SHA512Digest.new,
  );

  static const dhGexSha256 = SSHKexType._(
    name: 'diffie-hellman-group-exchange-sha256',
    digestFactory: SHA256Digest.new,
    isGroupExchange: true,
  );

  static const dhGexSha1 = SSHKexType._(
    name: 'diffie-hellman-group-exchange-sha1',
    digestFactory: SHA1Digest.new,
    isGroupExchange: true,
  );

  static const dh14Sha1 = SSHKexType._(
    name: 'diffie-hellman-group14-sha1',
    digestFactory: SHA1Digest.new,
  );

  static const dh14Sha256 = SSHKexType._(
    name: 'diffie-hellman-group14-sha256',
    digestFactory: SHA256Digest.new,
  );

  static const dh1Sha1 = SSHKexType._(
    name: 'diffie-hellman-group1-sha1',
    digestFactory: SHA1Digest.new,
  );

  const SSHKexType._({
    required this.name,
    required this.digestFactory,
    this.isGroupExchange = false,
  });

  /// The name of the algorithm. For example, `"ecdh-sha2-nistp256"`.
  @override
  final String name;

  final Digest Function() digestFactory;

  final bool isGroupExchange;

  Digest createDigest() => digestFactory();
}
