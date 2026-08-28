import 'dart:typed_data';

import 'package:dartssh2/src/kex/kex_nist.dart';
import 'package:dartssh2/src/ssh_errors.dart';
import 'package:test/test.dart';

void main() {
  test('SSHKexECDH.nistp256', () {
    final kex1 = SSHKexNist.p256();
    final kex2 = SSHKexNist.p256();
    final secret1 = kex1.computeSecret(kex2.publicKey);
    final secret2 = kex2.computeSecret(kex1.publicKey);
    expect(secret1, secret2);
  });

  test('SSHKexECDH.nistp384', () {
    final kex1 = SSHKexNist.p384();
    final kex2 = SSHKexNist.p384();
    final secret1 = kex1.computeSecret(kex2.publicKey);
    final secret2 = kex2.computeSecret(kex1.publicKey);
    expect(secret1, secret2);
  });

  test('SSHKexECDH.nistp521', () {
    final kex1 = SSHKexNist.p521();
    final kex2 = SSHKexNist.p521();
    final secret1 = kex1.computeSecret(kex2.publicKey);
    final secret2 = kex2.computeSecret(kex1.publicKey);
    expect(secret1, secret2);
  });

  group('SSHKexNist', () {
    test('generate keys and compute shared secret (P-256)', () {
      final kex = SSHKexNist.p256();
      final remoteKex = SSHKexNist.p256();

      final secret1 = kex.computeSecret(remoteKex.publicKey);
      final secret2 = remoteKex.computeSecret(kex.publicKey);

      expect(secret1, equals(secret2), reason: 'Shared secrets do not match.');
    });

    test('generate keys and compute shared secret (P-384)', () {
      final kex = SSHKexNist.p384();
      final remoteKex = SSHKexNist.p384();

      final secret1 = kex.computeSecret(remoteKex.publicKey);
      final secret2 = remoteKex.computeSecret(kex.publicKey);

      expect(secret1, equals(secret2), reason: 'Shared secrets do not match.');
    });

    test('generate keys and compute shared secret (P-521)', () {
      final kex = SSHKexNist.p521();
      final remoteKex = SSHKexNist.p521();

      final secret1 = kex.computeSecret(remoteKex.publicKey);
      final secret2 = remoteKex.computeSecret(kex.publicKey);

      expect(secret1, equals(secret2), reason: 'Shared secrets do not match.');
    });

    test('generate private key within valid range', () {
      final kex = SSHKexNist.p256();
      final privateKey = kex.privateKey;

      expect(privateKey, isNot(equals(BigInt.zero)),
          reason: 'Private key should not be zero.');
      expect(privateKey < kex.curve.n, isTrue,
          reason: 'Private key should be less than curve order.');
    });

    test('generate P-521 private key within valid range', () {
      final kex = SSHKexNist.p521();

      expect(kex.privateKey, greaterThan(BigInt.zero));
      expect(kex.privateKey, lessThan(kex.curve.n));
    });
  });

  group('SSHKexNist peer public key validation', () {
    test('rejects a point that fails to decode (garbage bytes)', () {
      final kex = SSHKexNist.p256();

      // Same length as an uncompressed P-256 point (0x04 || x(32) || y(32)),
      // but with an unrecognized point-format prefix byte, so pointycastle's
      // decodePoint() itself throws instead of returning a point.
      final garbage = Uint8List(65);
      garbage[0] = 0x09;

      expect(
        () => kex.computeSecret(garbage),
        throwsA(isA<SSHHandshakeError>()),
        reason: 'undecodable input must raise the protocol error, not a '
            'null-check or range error',
      );
    });

    test(
        'rejects a well-formed but off-curve point '
        '(invalid-curve attack)', () {
      final kex = SSHKexNist.p256();
      final legitimateRemote = SSHKexNist.p256();

      // Take a real, on-curve, correctly-encoded point and perturb the
      // y-coordinate by one. The length and prefix stay valid, so decoding
      // succeeds, but for almost every x there are only the two y values
      // satisfying y^2 = x^3 + a*x + b (mod p); y+1 is essentially never one
      // of them, so the point ends up off the curve.
      final offCurve = Uint8List.fromList(legitimateRemote.publicKey);
      offCurve[offCurve.length - 1] ^= 0x01;

      expect(
        () => kex.computeSecret(offCurve),
        throwsA(isA<SSHHandshakeError>()),
        reason: 'a decodable-but-off-curve point must be rejected as a '
            'protocol error, not crash with a null-check or range error',
      );
    });

    test('rejects the point at infinity', () {
      final kex = SSHKexNist.p256();

      expect(
        () => kex.computeSecret(Uint8List.fromList([0x00])),
        throwsA(isA<SSHHandshakeError>()),
      );
    });

    test('a valid exchange still succeeds (no regression)', () {
      final kex = SSHKexNist.p256();
      final remote = SSHKexNist.p256();

      final secret1 = kex.computeSecret(remote.publicKey);
      final secret2 = remote.computeSecret(kex.publicKey);

      expect(secret1, equals(secret2));
    });
  });
}
