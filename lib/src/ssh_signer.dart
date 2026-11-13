import 'dart:typed_data';

import 'package:dartssh2/src/ssh_key_pair.dart';

/// One key `publickey` authentication can offer, wherever its private half is
/// held: in this process ([SSHKeyPair.signer]) or in an agent
/// ([SSHAgentIdentity]).
abstract class SSHSigner {
  /// The algorithm the request names, which is also the one [sign] signs
  /// with: `rsa-sha2-256` for an RSA key, whose blob says `ssh-rsa`.
  String get type;

  /// The public key blob, as the wire carries it.
  Uint8List get publicKey;

  /// The encoded signature blob over [data].
  ///
  /// Asked only once the server has said it would accept [publicKey], so a
  /// signer that prompts (a hardware key, a password manager) prompts once,
  /// for the key that is used.
  Future<Uint8List> sign(Uint8List data);
}

extension SSHKeyPairSigner on SSHKeyPair {
  SSHSigner get signer => _KeyPairSigner(this);
}

class _KeyPairSigner implements SSHSigner {
  _KeyPairSigner(this._keyPair);

  final SSHKeyPair _keyPair;

  @override
  String get type => _keyPair.type;

  @override
  late final Uint8List publicKey = _keyPair.toPublicKey().encode();

  @override
  Future<Uint8List> sign(Uint8List data) async => _keyPair.sign(data).encode();
}
