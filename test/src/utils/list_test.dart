import 'dart:math';
import 'dart:typed_data';

import 'package:dartssh2/src/utils/list.dart';
import 'package:test/test.dart';

void main() {
  group('randomBytes', () {
    test('returns the requested number of bytes', () {
      expect(randomBytes(0), isEmpty);
      expect(randomBytes(32), hasLength(32));
    });

    test('uses the full byte range', () {
      final bytes = randomBytes(65536);
      expect(bytes, contains(255));
    });
  });

  group('constantTimeEquals', () {
    test('agrees with ListX.equals on a range of inputs', () {
      final random = Random(1234);
      for (var trial = 0; trial < 200; trial++) {
        final length = random.nextInt(64);
        final a = Uint8List.fromList(
          List<int>.generate(length, (_) => random.nextInt(256)),
        );

        // Identical copy.
        final same = Uint8List.fromList(a);
        expect(constantTimeEquals(a, same), a.equals(same));
        expect(constantTimeEquals(a, same), isTrue);

        // Same length, one byte flipped.
        if (length > 0) {
          final flipped = Uint8List.fromList(a);
          flipped[random.nextInt(length)] ^= 0xFF;
          expect(constantTimeEquals(a, flipped), a.equals(flipped));
          expect(constantTimeEquals(a, flipped), isFalse);
        }

        // Different length, sharing a common prefix.
        final longer = Uint8List.fromList([...a, 0]);
        expect(constantTimeEquals(a, longer), a.equals(longer));
        expect(constantTimeEquals(a, longer), isFalse);
      }
    });

    test('returns true for two empty lists', () {
      expect(constantTimeEquals(Uint8List(0), Uint8List(0)), isTrue);
    });

    test('returns false when only length differs', () {
      expect(constantTimeEquals(Uint8List(4), Uint8List(5)), isFalse);
    });
  });
}
