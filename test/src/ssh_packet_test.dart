import 'dart:typed_data';

import 'package:dartssh2/src/ssh_packet.dart';
import 'package:test/test.dart';

void main() {
  group('SSHPacket.pack', () {
    // Regression for T-05: padding used to be `Uint8List(padding)`, i.e. all
    // zero bytes, which RFC 4253 §6 forbids (padding "SHOULD consist of
    // random bytes"). This is the padding source used by the plaintext,
    // AES-CTR and AES-CBC send paths.
    test(
        'uses random padding that differs between otherwise-identical '
        'packets', () {
      final payload = Uint8List.fromList(List<int>.generate(20, (i) => i));

      final first = SSHPacket.pack(payload, align: 8);
      final second = SSHPacket.pack(payload, align: 8);

      final firstPaddingLength = SSHPacket.readPaddingLength(first);
      final secondPaddingLength = SSHPacket.readPaddingLength(second);
      expect(firstPaddingLength, greaterThanOrEqualTo(4));
      expect(secondPaddingLength, greaterThanOrEqualTo(4));

      final firstPadding = Uint8List.sublistView(
        first,
        first.length - firstPaddingLength,
      );
      final secondPadding = Uint8List.sublistView(
        second,
        second.length - secondPaddingLength,
      );

      // Not all zero...
      expect(firstPadding, isNot(everyElement(0)));
      // ...and not the same across two independently generated packets.
      expect(firstPadding, isNot(equals(secondPadding)));
    });

    test('still produces a correctly aligned and framed packet', () {
      final payload = Uint8List.fromList(List<int>.generate(11, (i) => i));
      final packet = SSHPacket.pack(payload, align: 8);

      final packetLength = SSHPacket.readPacketLength(packet);
      expect(packet.length, 4 + packetLength);
      expect(packet.length % 8, 0);

      final paddingLength = SSHPacket.readPaddingLength(packet);
      expect(
        Uint8List.sublistView(packet, 5, 5 + payload.length),
        payload,
      );
      expect(1 + payload.length + paddingLength, packetLength);
    });
  });
}
