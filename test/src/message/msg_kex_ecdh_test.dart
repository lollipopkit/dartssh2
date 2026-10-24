import 'dart:typed_data';

import 'package:dartssh2/src/message/base.dart';
import 'package:test/test.dart';

void main() {
  test('SSH_Message_KexECDH_Reply: K_S, then Q_S, then the signature', () {
    final hostKey = Uint8List.fromList([1, 1]);
    final ecdhKey = Uint8List.fromList([2, 2, 2]);
    final signature = Uint8List.fromList([3]);
    final encoded = SSH_Message_KexECDH_Reply(
      hostPublicKey: hostKey,
      ecdhPublicKey: ecdhKey,
      signature: signature,
    ).encode();

    // RFC 5656 §4: byte 31, string K_S, string Q_S, string signature.
    expect(encoded, [31, 0, 0, 0, 2, 1, 1, 0, 0, 0, 3, 2, 2, 2, 0, 0, 0, 1, 3]);

    final decoded = SSH_Message_KexECDH_Reply.decode(encoded);
    expect(decoded.hostPublicKey, hostKey);
    expect(decoded.ecdhPublicKey, ecdhKey);
    expect(decoded.signature, signature);
  });
}
