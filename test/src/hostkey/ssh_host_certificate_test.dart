import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:dartssh2/src/hostkey/hostkey_cert.dart';
import 'package:dartssh2/src/ssh_errors.dart';
import 'package:test/test.dart';

/// Certificates made by `ssh-keygen -s` (OpenSSH 10.3), with the host keys
/// they certify. The private keys were not kept.
Uint8List _blob(String name) {
  final line = File('test/fixtures/host_cert/$name').readAsStringSync();
  return base64.decode(line.split(' ')[1]);
}

Matcher _refused(String why) => throwsA(
      isA<SSHHostkeyError>().having((e) => e.message, 'message', contains(why)),
    );

void main() {
  test('the certified key is the host key, as OpenSSH fingerprints it', () {
    for (final (cert, key) in [
      ('ed25519_by_ed25519-cert.pub', 'host_ed25519.pub'),
      ('ecdsa_by_rsa-cert.pub', 'host_ecdsa.pub'),
      ('rsa_by_ecdsa-cert.pub', 'host_rsa.pub'),
    ]) {
      expect(SSHHostCertificate.decode(_blob(cert)).publicKey, _blob(key),
          reason: cert);
    }
  });

  test('what a host certificate says is read', () {
    final cert = SSHHostCertificate.decode(_blob('ed25519_by_ed25519-cert.pub'));
    expect(cert.type, 'ssh-ed25519-cert-v01@openssh.com');
    expect(cert.certType, SSHHostCertificate.hostType);
    expect(cert.keyId, 'ed25519-by-ed25519');
    expect(cert.principals, ['host.example']);
    expect(cert.criticalOptions, isEmpty);
    // `forever` is all ones on the wire.
    expect(cert.validBefore, isNegative);
  });

  test('signed by an Ed25519, RSA or ECDSA authority, it verifies', () {
    for (final name in [
      'ed25519_by_ed25519-cert.pub',
      'ecdsa_by_rsa-cert.pub',
      'rsa_by_ecdsa-cert.pub',
    ]) {
      expect(() => SSHHostCertificate.decode(_blob(name)).verify(),
          returnsNormally,
          reason: name);
    }
  });

  test('out of date, it is refused, and says so', () {
    final cert = SSHHostCertificate.decode(_blob('expired-cert.pub'));
    expect(() => cert.verify(), _refused('expired'));
    expect(() => cert.verify(now: DateTime.utc(2019)), _refused('not yet valid'));
    expect(() => cert.verify(now: DateTime.utc(2020, 1, 1, 12)), returnsNormally);
  });

  test('a user certificate is not a host certificate', () {
    final cert = SSHHostCertificate.decode(_blob('user-cert.pub'));
    expect(() => cert.verify(), _refused('non-host certificate'));
  });

  test('a critical option it does not know refuses the certificate', () {
    final cert = SSHHostCertificate.decode(_blob('critical-cert.pub'));
    expect(cert.criticalOptions, ['test@example.com']);
    expect(() => cert.verify(), _refused('critical options'));
  });

  test('an authority signing with SHA-1 is refused, as OpenSSH refuses it', () {
    final cert = SSHHostCertificate.decode(_blob('sha1_ca-cert.pub'));
    expect(() => cert.verify(), _refused('refused algorithm ssh-rsa'));
  });

  test('a certificate altered after signing does not verify', () {
    final data = _blob('ed25519_by_ed25519-cert.pub');
    final principal = utf8.encode('host.example');
    final at = _indexOf(data, principal);
    data[at] ^= 1; // `iost.example`: still well formed, no longer signed
    final cert = SSHHostCertificate.decode(data);
    expect(cert.principals.single, isNot('host.example'));
    expect(() => cert.verify(), _refused('signature is invalid'));
  });

  test('a plain host key is not a certificate', () {
    expect(SSHHostCertificate.isCertificate(_blob('host_ed25519.pub')), isFalse);
    expect(
      SSHHostCertificate.isCertificate(_blob('ed25519_by_ed25519-cert.pub')),
      isTrue,
    );
    expect(() => SSHHostCertificate.decode(_blob('host_ed25519.pub')),
        _refused('Not a host certificate'));
  });
}

int _indexOf(List<int> data, List<int> part) {
  for (var i = 0; i + part.length <= data.length; i++) {
    var match = true;
    for (var j = 0; j < part.length && match; j++) {
      match = data[i + j] == part[j];
    }
    if (match) return i;
  }
  throw StateError('not found');
}
