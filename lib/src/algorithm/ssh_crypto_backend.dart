import 'dart:typed_data';

import 'package:pointycastle/api.dart';

/// A faster source for the record layer's symmetric primitives.
///
/// dartssh2 computes AES and HMAC with pointycastle — pure Dart, on whichever
/// isolate owns the connection. That is the right default: it needs nothing
/// from the embedder and runs on every platform Dart does. But in an app that
/// isolate is usually the one drawing frames, and a terminal streaming output
/// or a poll across many servers then puts AES and SHA-2 in front of layout.
/// There is nowhere to move the work to either — the socket under a transport
/// may be a jump connection wrapping a second `SSHClient` or a `ProxyCommand`
/// wrapping a `Process`, neither of which can be sent to another isolate.
///
/// So an embedder that has a native implementation registers it in
/// [sshCryptoBackend] and the work stops being expensive where it is. Every
/// method may answer `null` for something it does not implement, and the
/// built-in is used for those unchanged — a backend covering one cipher is a
/// valid backend, and one covering nothing behaves exactly like no backend.
///
/// Whatever is returned is used for one direction of one connection and is
/// never handed to another, so it may hold as much state as it needs to.
///
/// Every method has a default that answers `null`, rather than being abstract.
/// The seam grows — it started at the record cipher and has since taken on the
/// key exchange, signatures and the key-encryption KDF — and an added method
/// that were abstract would break every implementer on a release that has
/// nothing to do with them.
abstract class SSHCryptoBackend {
  const SSHCryptoBackend();

  /// A cipher for [algorithm] under [key] and [iv], or `null` to leave it to
  /// pointycastle.
  ///
  /// [algorithm] is the SSH name as it appears on the wire — `aes256-ctr`,
  /// `aes128-cbc`. The result is already keyed: [BlockCipher.init] is not
  /// called on it afterwards.
  ///
  /// Implement [SSHBulkBlockCipher] as well when a call is not free, or every
  /// packet is walked a block at a time.
  BlockCipher? createBlockCipher(
    String algorithm,
    Uint8List key,
    Uint8List iv, {
    required bool forEncryption,
  }) =>
      null;

  /// A MAC for [algorithm] under [key], or `null` to leave it to pointycastle.
  ///
  /// [algorithm] is the name of the underlying HMAC — `hmac-sha2-256` — with
  /// any `-etm@openssh.com` suffix already removed, since encrypt-then-MAC
  /// changes what is fed in rather than how the tag is computed. [macSize] is
  /// the tag length in bytes *after* truncation, which is the only thing the
  /// `-96` variants change.
  ///
  /// The result is already keyed: [Mac.init] is not called on it afterwards.
  Mac? createMac(String algorithm, Uint8List key, int macSize) => null;

  /// A fresh x25519 keypair as `(privateKey, publicKey)`, or `null`.
  ///
  /// The private key is the backend's to generate: a key exchange scalar a
  /// caller could supply is one an attacker could replay. Both halves are 32
  /// bytes.
  (Uint8List, Uint8List)? x25519KeyPair() => null;

  /// The x25519 shared secret, or `null` to leave it to the built-in.
  ///
  /// Throws rather than answering `null` when [peerPublicKey] is a low-order
  /// point: that is a peer forcing a known secret, and a caller that read it
  /// as "unsupported" would fall back and complete the exchange anyway.
  Uint8List? x25519SharedSecret(
          Uint8List privateKey, Uint8List peerPublicKey) =>
      null;

  /// An Ed25519 signature over [message], or `null`.
  ///
  /// [privateKey] is the 64-byte blob OpenSSH stores — a 32-byte seed followed
  /// by the public key it expands to.
  Uint8List? ed25519Sign(Uint8List privateKey, Uint8List message) => null;

  /// Whether [signature] is [message] signed by [publicKey], or `null`.
  ///
  /// The three-valued result is the point: `null` means this backend does not
  /// do Ed25519 and the built-in should answer, `false` means the signature is
  /// not valid. Collapsing them would turn "unsupported" into "trusted".
  bool? ed25519Verify(
    Uint8List publicKey,
    Uint8List message,
    Uint8List signature,
  ) =>
      null;

  /// An ECDSA signature over [message] as `(r, s)`, or `null`.
  ///
  /// [curveId] is the SSH name — `nistp256` and so on — which fixes the hash
  /// with it. The result need not match what the built-in would produce for
  /// the same input: ECDSA admits a nonce, and a backend may well be
  /// deterministic where pointycastle is randomised.
  (BigInt, BigInt)? ecdsaSign(String curveId, BigInt d, Uint8List message) =>
      null;

  /// Whether `(r, s)` is [message] signed by [q], or `null`.
  ///
  /// [q] is the uncompressed SEC1 point as SSH sends it, `0x04` prefix
  /// included. Three-valued for the reason [ed25519Verify] gives.
  bool? ecdsaVerify(
    String curveId,
    Uint8List q,
    Uint8List message,
    BigInt r,
    BigInt s,
  ) =>
      null;

  /// `bcrypt_pbkdf` of [passphrase] under [salt], or `null`.
  ///
  /// [rounds] comes out of the key file and is not a backend's to choose: the
  /// cost is the point, and only who pays it faster changes.
  Uint8List? bcryptPbkdf(
    Uint8List passphrase,
    Uint8List salt,
    int rounds,
    int outputLength,
  ) =>
      null;
}

/// The backend in force, or `null` for pointycastle throughout.
///
/// Read when a connection installs its keys, so a change takes effect on the
/// next connection and never mid-session.
SSHCryptoBackend? sshCryptoBackend;

/// A [BlockCipher] that can transform a whole packet in one call.
///
/// `BlockCipherX.processAll` otherwise walks its input a block at a time. For
/// an implementation in this isolate that is the cheapest thing to do; for one
/// that has to cross a boundary it is the most expensive, turning a 32 KB
/// packet into two thousand crossings.
abstract interface class SSHBulkBlockCipher implements BlockCipher {
  /// [data], transformed and the cipher advanced past it.
  ///
  /// Length is a whole number of [BlockCipher.blockSize] blocks, which is what
  /// the packet framing guarantees.
  Uint8List processBulk(Uint8List data);
}
