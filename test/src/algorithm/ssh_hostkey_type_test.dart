import 'package:dartssh2/dartssh2.dart';
import 'package:test/test.dart';

void main() {
  group('SSHHostkeyType', () {
    test('Static constants are defined correctly', () {
      expect(SSHHostkeyType.rsaSha1.name, equals('ssh-rsa'));
      expect(SSHHostkeyType.rsaSha256.name, equals('rsa-sha2-256'));
      expect(SSHHostkeyType.rsaSha512.name, equals('rsa-sha2-512'));
      expect(SSHHostkeyType.ecdsa256.name, equals('ecdsa-sha2-nistp256'));
      expect(SSHHostkeyType.ecdsa384.name, equals('ecdsa-sha2-nistp384'));
      expect(SSHHostkeyType.ecdsa521.name, equals('ecdsa-sha2-nistp521'));
      expect(SSHHostkeyType.ed25519.name, equals('ssh-ed25519'));
    });

    test('a certificate signs with the key it certifies', () {
      final certs = {
        SSHHostkeyType.rsaSha1Cert: SSHHostkeyType.rsaSha1,
        SSHHostkeyType.rsaSha256Cert: SSHHostkeyType.rsaSha256,
        SSHHostkeyType.rsaSha512Cert: SSHHostkeyType.rsaSha512,
        SSHHostkeyType.ecdsa256Cert: SSHHostkeyType.ecdsa256,
        SSHHostkeyType.ecdsa384Cert: SSHHostkeyType.ecdsa384,
        SSHHostkeyType.ecdsa521Cert: SSHHostkeyType.ecdsa521,
        SSHHostkeyType.ed25519Cert: SSHHostkeyType.ed25519,
      };
      for (final MapEntry(key: cert, value: key) in certs.entries) {
        expect(cert.isCertificate, isTrue);
        expect(cert.keyType, same(key));
        expect(cert.name, endsWith('-cert-v01@openssh.com'));
        expect(key.isCertificate, isFalse);
        expect(key.keyType, same(key));
      }
      expect(SSHHostkeyType.rsaSha1Cert.name, 'ssh-rsa-cert-v01@openssh.com');
      expect(SSHHostkeyType.rsaSha512Cert.name,
          'rsa-sha2-512-cert-v01@openssh.com');
    });

    test('by default, each certificate is just before the key it certifies',
        () {
      final offered = const SSHAlgorithms().hostkey;
      // Without the certificates, the keys and their order are as before, so
      // a server with no certificate negotiates the key it always did.
      expect(offered.where((t) => !t.isCertificate), [
        SSHHostkeyType.ed25519,
        SSHHostkeyType.ecdsa521,
        SSHHostkeyType.ecdsa384,
        SSHHostkeyType.ecdsa256,
        SSHHostkeyType.rsaSha512,
        SSHHostkeyType.rsaSha256,
      ]);
      for (var i = 0; i < offered.length; i++) {
        if (offered[i].isCertificate) {
          expect(offered[i + 1], same(offered[i].keyType));
        }
      }
    });

    test('toString() returns correct format', () {
      expect(
          SSHHostkeyType.rsaSha1.toString(), equals('SSHHostkeyType(ssh-rsa)'));
      expect(SSHHostkeyType.rsaSha256.toString(),
          equals('SSHHostkeyType(rsa-sha2-256)'));
      expect(SSHHostkeyType.rsaSha512.toString(),
          equals('SSHHostkeyType(rsa-sha2-512)'));
      expect(SSHHostkeyType.ecdsa256.toString(),
          equals('SSHHostkeyType(ecdsa-sha2-nistp256)'));
      expect(SSHHostkeyType.ecdsa384.toString(),
          equals('SSHHostkeyType(ecdsa-sha2-nistp384)'));
      expect(SSHHostkeyType.ecdsa521.toString(),
          equals('SSHHostkeyType(ecdsa-sha2-nistp521)'));
      expect(SSHHostkeyType.ed25519.toString(),
          equals('SSHHostkeyType(ssh-ed25519)'));
    });
  });
}
