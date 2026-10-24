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
      final certificate = SSHHostCertificate.decode(_blob(cert));
      expect(certificate.publicKey, _blob(key), reason: cert);
      expect(certificate.type, endsWith('-cert-v01@openssh.com'));
    }
  });

  // With no authority trusted none of this says anything; OpenSSH falls back
  // to the plain key in the same case and does not look at it either.
  test('decoding alone refuses nothing the key is fine for', () {
    for (final name in [
      'expired-cert.pub',
      'user-cert.pub',
      'critical-cert.pub',
      'sha1_ca-cert.pub',
    ]) {
      expect(SSHHostCertificate.decode(_blob(name)).publicKey,
          _blob('host_ed25519.pub'),
          reason: name);
    }
  });

  group('verified for a trusted authority', () {
    const host = ['host.example'];

    test('signed by an Ed25519, RSA or ECDSA authority, it verifies', () {
      for (final name in [
        'ed25519_by_ed25519-cert.pub',
        'ecdsa_by_rsa-cert.pub',
        'rsa_by_ecdsa-cert.pub',
      ]) {
        expect(
            () =>
                SSHHostCertificate.decode(_blob(name)).verify(principals: host),
            returnsNormally,
            reason: name);
      }
    });

    test('what it says is read, "forever" included', () {
      final cert =
          SSHHostCertificate.decode(_blob('ed25519_by_ed25519-cert.pub'));
      expect(cert.certType, SSHHostCertificate.hostType);
      expect(cert.keyId, 'ed25519-by-ed25519');
      expect(cert.principals, host);
      expect(cert.criticalOptions, isEmpty);
      expect(cert.validBefore, (BigInt.one << 64) - BigInt.one);
    });

    test('out of date, it is refused, and says so', () {
      final cert = SSHHostCertificate.decode(_blob('expired-cert.pub'));
      expect(() => cert.verify(principals: host), _refused('expired'));
      expect(() => cert.verify(principals: host, now: DateTime.utc(2019)),
          _refused('not yet valid'));
      expect(
          () =>
              cert.verify(principals: host, now: DateTime.utc(2020, 1, 1, 12)),
          returnsNormally);
    });

    test('for a name it does not list, it is refused', () {
      final cert =
          SSHHostCertificate.decode(_blob('ed25519_by_ed25519-cert.pub'));
      expect(() => cert.verify(principals: ['other.example']),
          _refused('not valid for other.example'));
      expect(() => cert.verify(principals: ['other.example', 'host.example']),
          returnsNormally);
    });

    test('a user certificate is not a host certificate', () {
      final cert = SSHHostCertificate.decode(_blob('user-cert.pub'));
      expect(() => cert.verify(principals: host),
          _refused('non-host certificate'));
    });

    test('a critical option it does not know refuses it', () {
      final cert = SSHHostCertificate.decode(_blob('critical-cert.pub'));
      expect(cert.criticalOptions, ['test@example.com']);
      expect(() => cert.verify(principals: host), _refused('critical options'));
    });

    test('an authority signing with SHA-1 is refused, as OpenSSH refuses it',
        () {
      final cert = SSHHostCertificate.decode(_blob('sha1_ca-cert.pub'));
      expect(() => cert.verify(principals: host),
          _refused('refused algorithm ssh-rsa'));
    });

    test('altered after signing, it does not verify', () {
      final data = _blob('ed25519_by_ed25519-cert.pub');
      final at = _indexOf(data, utf8.encode('ed25519-by-ed25519'));
      data[at] ^= 1; // the key id: still well formed, no longer signed
      expect(() => SSHHostCertificate.decode(data).verify(principals: host),
          _refused('signature is invalid'));
    });
  });

  test('an ECDSA certificate whose curve is not its type is refused', () {
    final data = _blob('ecdsa_by_rsa-cert.pub');
    final curve = utf8.encode('nistp384');
    // The curve string, after the type that also names it.
    final at = _indexOf(data, curve, from: _indexOf(data, curve) + 1);
    data.setRange(at, at + curve.length, utf8.encode('nistp521'));
    expect(() => SSHHostCertificate.decode(data),
        _refused('curve nistp521 does not match'));
  });

  test('a plain host key is not a certificate', () {
    expect(() => SSHHostCertificate.decode(_blob('host_ed25519.pub')),
        _refused('Not a host certificate'));
  });
}

int _indexOf(List<int> data, List<int> part, {int from = 0}) {
  for (var i = from; i + part.length <= data.length; i++) {
    var match = true;
    for (var j = 0; j < part.length && match; j++) {
      match = data[i + j] == part[j];
    }
    if (match) return i;
  }
  throw StateError('not found');
}
