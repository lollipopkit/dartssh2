import 'dart:typed_data';

/// Splits OpenSSH ChaCha20-Poly1305 key material into length and payload keys.
///
/// OpenSSH derives 64 bytes per direction. Per PROTOCOL.chacha20poly1305:
/// "The first 256 bits constitute K_2 and the second 256 bits become K_1",
/// where K_1 encrypts the packet length field and K_2 encrypts the payload
/// and derives the Poly1305 one-time key. So the *second* half is the length
/// key, not the first.
({Uint8List lenKey, Uint8List encKey}) splitOpenSSHChaChaKeys(
  Uint8List keyMaterial,
) {
  if (keyMaterial.length != 64) {
    throw ArgumentError.value(
      keyMaterial.length,
      'keyMaterial.length',
      'OpenSSH ChaCha20-Poly1305 requires exactly 64 bytes of key material',
    );
  }

  return (
    encKey: Uint8List.sublistView(keyMaterial, 0, 32), // K_2
    lenKey: Uint8List.sublistView(keyMaterial, 32, 64), // K_1
  );
}
