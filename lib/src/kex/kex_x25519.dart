import 'dart:typed_data';

import 'package:dartssh2/src/algorithm/ssh_crypto_backend.dart';
import 'package:dartssh2/src/ssh_kex.dart';
import 'package:dartssh2/src/utils/compute.dart';
import 'package:dartssh2/src/utils/bigint.dart';
import 'package:dartssh2/src/utils/list.dart';
import 'package:pinenacl/tweetnacl.dart';

class SSHKexX25519 implements SSHKexECDH {
  /// Randomly generated private key.
  final Uint8List privateKey;

  /// Public key computed from the private key.
  @override
  final Uint8List publicKey;

  factory SSHKexX25519() {
    final privateKey = randomBytes(32);
    final publicKey = _ScalarMult.scalseMultBase(privateKey);
    return SSHKexX25519._(
      privateKey: privateKey,
      publicKey: publicKey,
    );
  }

  SSHKexX25519._({required this.privateKey, required this.publicKey});

  /// The isolate is what makes this async, and a backend removes the need
  /// for one: scalar multiplication is sub-millisecond in Dart, which is worth
  /// hiding behind `Isolate.run` and not worth spawning an isolate for once it
  /// is microseconds. The signature stays a `Future` so callers do not have to
  /// know which happened.
  static Future<SSHKexX25519> createAsync() async {
    final native = sshCryptoBackend?.x25519KeyPair();
    if (native != null) {
      return SSHKexX25519._(privateKey: native.$1, publicKey: native.$2);
    }
    final (privateKey, publicKey) =
        await sshCompute(_computeX25519KeyPair, null);
    return SSHKexX25519._(
      privateKey: privateKey,
      publicKey: publicKey,
    );
  }

  @override
  BigInt computeSecret(Uint8List remotePublicKey) {
    final secret = _ScalarMult.scalseMult(privateKey, remotePublicKey);
    return decodeBigIntWithSign(1, secret);
  }

  Future<BigInt> computeSecretAsync(Uint8List remotePublicKey) async {
    // Checked here and not only in `_ScalarMult`, which a backend does not go
    // through: a peer key of the wrong length should fail the same way with a
    // backend installed as without one.
    if (remotePublicKey.length != _ScalarMult.groupElementLength) {
      throw ArgumentError('p must be 32 bytes long');
    }
    final native = sshCryptoBackend?.x25519SharedSecret(
      privateKey,
      remotePublicKey,
    );
    if (native != null) return decodeBigIntWithSign(1, native);
    final secret = await sshCompute(
      _computeX25519Secret,
      (privateKey, remotePublicKey),
    );
    return decodeBigIntWithSign(1, secret);
  }
}

(Uint8List, Uint8List) _computeX25519KeyPair(void _) {
  final privateKey = randomBytes(32);
  final publicKey = _ScalarMult.scalseMultBase(privateKey);
  return (privateKey, publicKey);
}

Uint8List _computeX25519Secret((Uint8List, Uint8List) data) {
  return _ScalarMult.scalseMult(data.$1, data.$2);
}

/// Scalar multiplication, Implements curve25519.
class _ScalarMult {
  /// Length of scalar in bytes.
  static final int _scalarLength = 32;

  /// Length of group element in bytes.
  static final int groupElementLength = 32;

  /// Multiplies an integer n by a group element p and returns the resulting
  /// group element.
  static Uint8List scalseMult(Uint8List n, Uint8List p) {
    if (n.length != _scalarLength) {
      throw ArgumentError('n must be 32 bytes long');
    }

    if (p.length != groupElementLength) {
      throw ArgumentError('p must be 32 bytes long');
    }

    final q = Uint8List(_scalarLength);

    TweetNaCl.crypto_scalarmult(q, n, p);

    return q;
  }

  /// Multiplies an integer n by a standard group element and returns the
  /// resulting group element.
  static Uint8List scalseMultBase(Uint8List n) {
    if (n.length != _scalarLength) {
      throw ArgumentError('n must be 32 bytes long');
    }

    final q = Uint8List(_scalarLength);

    TweetNaCl.crypto_scalarmult_base(q, n);

    return q;
  }
}
