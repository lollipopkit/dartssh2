import 'dart:typed_data';

import 'package:dartssh2/src/ssh_packet.dart';
import 'package:test/test.dart';

void main() {
  test('pack adds random padding bytes per RFC 4253 section 6', () {
    final originalGenerator = SSHPacket.randomPaddingGenerator;
    try {
      var generatorCalls = 0;
      SSHPacket.randomPaddingGenerator = (length) {
        generatorCalls++;
        final bytes = Uint8List(length);
        for (var i = 0; i < length; i++) {
          bytes[i] = (i + 1) & 0xff;
        }
        return bytes;
      };

      final payload = Uint8List.fromList([1, 2, 3, 4]);
      const align = 8;
      final packet = SSHPacket.pack(payload, align: align);

      final paddingLength = SSHPacket.readPaddingLength(packet);
      expect(paddingLength, greaterThanOrEqualTo(4));
      expect(generatorCalls, 1);

      final paddingStart = SSHPacket.headerLength + payload.length;
      final paddingBytes =
          packet.sublist(paddingStart, paddingStart + paddingLength);

      final expectedPadding = Uint8List.fromList(
        List<int>.generate(paddingLength, (index) => (index + 1) & 0xff),
      );

      expect(paddingBytes, expectedPadding);
    } finally {
      SSHPacket.randomPaddingGenerator = originalGenerator;
    }
  });
}
