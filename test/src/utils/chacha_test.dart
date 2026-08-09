import 'dart:typed_data';

import 'package:dartssh2/src/utils/chacha.dart';
import 'package:test/test.dart';

void main() {
  group('splitOpenSSHChaChaKeys', () {
    // PROTOCOL.chacha20poly1305: "The first 256 bits constitute K_2 and the
    // second 256 bits become K_1", where K_1 encrypts the length field and
    // K_2 encrypts the payload. So the payload key comes first and the length
    // key second — this test previously asserted the reverse.
    test('splits length and payload keys in OpenSSH order', () {
      final material = Uint8List.fromList(List<int>.generate(64, (i) => i));

      final (lenKey: lenKey, encKey: encKey) = splitOpenSSHChaChaKeys(material);

      expect(
          encKey, equals(Uint8List.fromList(List<int>.generate(32, (i) => i))));
      expect(lenKey,
          equals(Uint8List.fromList(List<int>.generate(32, (i) => i + 32))));
    });

    test('throws ArgumentError for incorrect key size', () {
      final material = Uint8List(63);

      expect(
        () => splitOpenSSHChaChaKeys(material),
        throwsA(isA<ArgumentError>()),
      );
    });
  });
}
