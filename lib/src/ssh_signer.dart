import 'dart:typed_data';

import 'package:dartssh2/src/hostkey/hostkey_rsa.dart';
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

  /// A signer using [algorithm] for this key, or `null` if this key cannot sign
  /// under [algorithm].
  SSHSigner? signerFor(String algorithm) {
    final self = this;
    if (self is SSHRsaKeyPair) {
      if (algorithm == SSHRsaSignatureType.sha256 ||
          algorithm == SSHRsaSignatureType.sha512 ||
          algorithm == SSHRsaSignatureType.sha1) {
        return _RsaKeyPairSigner(self, algorithm);
      }
      return null;
    }
    return algorithm == type ? signer : null;
  }
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

class _RsaKeyPairSigner implements SSHSigner {
  _RsaKeyPairSigner(this._keyPair, this.type);

  final SSHRsaKeyPair _keyPair;

  @override
  final String type;

  @override
  late final Uint8List publicKey = _keyPair.toPublicKey().encode();

  @override
  Future<Uint8List> sign(Uint8List data) async =>
      _keyPair.signWith(data, type).encode();
}
