import 'dart:typed_data';

import 'package:dartssh2/src/kex/kex_x25519.dart';
import 'package:dartssh2/src/ssh_errors.dart';
import 'package:test/test.dart';

void main() {
  test('SSHKexX25519', () {
    final kex1 = SSHKexX25519();
    final kex2 = SSHKexX25519();
    final secret1 = kex1.computeSecret(kex2.publicKey);
    final secret2 = kex2.computeSecret(kex1.publicKey);
    expect(secret1, secret2);
  });
  group('SSHKexX25519', () {
    late SSHKexX25519 kex;

    setUp(() {
      kex = SSHKexX25519();
    });

    test('should generate a 32-byte private key', () {
      expect(kex.privateKey.length, equals(32));
    });

    test('should generate a 32-byte public key', () {
      expect(kex.publicKey.length, equals(32));
    });

    test('should compute shared secret correctly', () {
      // Generate a new SSHKexX25519 instance to act as the remote party
      final remoteKex = SSHKexX25519();

      // Compute the shared secret using the local private key and remote public key
      final sharedSecret = kex.computeSecret(remoteKex.publicKey);

      // Compute the shared secret using the remote private key and local public key
      final remoteSharedSecret = remoteKex.computeSecret(kex.publicKey);

      // Assert that both shared secrets are equal
      expect(sharedSecret, equals(remoteSharedSecret));
    });

    test('should handle invalid public key length in computeSecret', () {
      final invalidPublicKey = Uint8List(31); // Invalid length

      expect(() => kex.computeSecret(invalidPublicKey),
          throwsA(isA<SSHHandshakeError>()));
    });

    test('should handle valid inputs for scalar multiplication indirectly', () {
      // This test is intended to indirectly verify the behavior of scalar multiplication
      // through the public method computeSecret.

      final validPublicKey = kex.publicKey;

      // Test valid scenario using computeSecret
      final validKex = SSHKexX25519();
      final validSharedSecret = validKex.computeSecret(validPublicKey);

      expect(validSharedSecret, isNotNull);
      expect(validSharedSecret.bitLength, greaterThan(0));
    });
  });

  group('SSHKexX25519 public key length check (RFC 8731 §3)', () {
    // "Clients and servers MUST also abort if the length of the received
    // public keys are not the expected lengths."
    for (final length in [0, 1, 31, 33, 64]) {
      test('a $length-byte peer public key is rejected', () {
        final kex = SSHKexX25519();

        expect(
          () => kex.computeSecret(Uint8List(length)),
          throwsA(isA<SSHHandshakeError>()),
        );
      });
    }

    test('the check runs before scalar multiplication', () {
      // A 33-byte key whose first 32 bytes are a valid public key would
      // otherwise be silently truncated and accepted by scalseMult.
      final peer = SSHKexX25519();
      final overlong = Uint8List(33)..setRange(0, 32, peer.publicKey);

      expect(
        () => SSHKexX25519().computeSecret(overlong),
        throwsA(isA<SSHHandshakeError>()),
      );
    });
  });

  group('SSHKexX25519 small-order public key rejection (RFC 8731 §3)', () {
    test(
        'all-zero peer public key yields an all-zero secret and is '
        'rejected', () {
      final kex = SSHKexX25519();
      final allZero = Uint8List(32);

      expect(
        () => kex.computeSecret(allZero),
        throwsA(isA<SSHHandshakeError>()),
      );
    });

    test('a known order-2 small-order point is rejected', () {
      final kex = SSHKexX25519();

      // A canonical order-2 point on Curve25519 (RFC 7748 §5.2 / widely
      // cited "small order points" test vectors). Multiplying it by any
      // private scalar yields an all-zero shared secret, so any peer that
      // sends it (or any other small-order point) can force a known,
      // attacker-predictable secret unless it is rejected.
      final order2 = Uint8List.fromList([
        0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, //
        0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f, 0xc4, 0x6a, //
        0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, //
        0x86, 0x62, 0x05, 0x16, 0x5f, 0x49, 0xb8, 0x00, //
      ]);

      expect(
        () => kex.computeSecret(order2),
        throwsA(isA<SSHHandshakeError>()),
      );
    });

    test('a normal exchange still succeeds (no regression)', () {
      final kex1 = SSHKexX25519();
      final kex2 = SSHKexX25519();

      final secret1 = kex1.computeSecret(kex2.publicKey);
      final secret2 = kex2.computeSecret(kex1.publicKey);

      expect(secret1, equals(secret2));
    });
  });
}
