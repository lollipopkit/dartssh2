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
/// [sshCryptoBackend] and the work stops being expensive where it is. Both
/// methods may answer `null` for an algorithm they do not implement, and
/// pointycastle is used for those unchanged — a backend covering one cipher is
/// a valid backend, and one covering none behaves exactly like no backend.
///
/// Whatever is returned is used for one direction of one connection and is
/// never handed to another, so it may hold as much state as it needs to.
abstract interface class SSHCryptoBackend {
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
  });

  /// A MAC for [algorithm] under [key], or `null` to leave it to pointycastle.
  ///
  /// [algorithm] is the name of the underlying HMAC — `hmac-sha2-256` — with
  /// any `-etm@openssh.com` suffix already removed, since encrypt-then-MAC
  /// changes what is fed in rather than how the tag is computed. [macSize] is
  /// the tag length in bytes *after* truncation, which is the only thing the
  /// `-96` variants change.
  ///
  /// The result is already keyed: [Mac.init] is not called on it afterwards.
  Mac? createMac(String algorithm, Uint8List key, int macSize);
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
