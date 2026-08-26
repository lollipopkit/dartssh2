// Tests for the 32-bit-pair helpers in lib/src/utils/int.dart, which
// replace ByteData.getUint64/setUint64 (unsupported when compiled to
// JavaScript -- see W-01 in AUDIT.md). This file is web-safe on purpose so
// it's exercised by both the VM and the web (chrome) CI job.
//
// Two things are deliberately kept out of this file because they simply
// cannot compile under dart2js:
//   - Any integer literal above 2^53 that isn't itself an exact power of
//     two ("The integer literal ... can't be represented exactly in
//     JavaScript" is a *compile* error, not a runtime one) -- so every test
//     value here is built from two 32-bit halves via [combineUint32Pair] or
//     [ByteData.setUint32] instead of written as a single wide literal.
//   - Values whose high word is large enough that combining them into a
//     single int would need more than 53 bits: [kIntIsImprecise] makes
//     [combineUint32Pair]/[splitUint32Pair] throw for those on purpose (see
//     the doc comment on [combineUint32Pair]). The full 64-bit-range case,
//     which only makes sense on a platform where it doesn't throw, lives in
//     the companion VM-only file int_vm_uint64_boundary_test.dart instead.

import 'dart:typed_data';

import 'package:dartssh2/src/utils/int.dart';
import 'package:test/test.dart';

void main() {
  group('combineUint32Pair / splitUint32Pair', () {
    // Every pair here has high < 0x200000, so the combined value is always
    // <= 2^53 and exactly representable regardless of platform.
    final cases = <String, Uint32Pair>{
      'zero': (high: 0, low: 0),
      'one': (high: 0, low: 1),
      'low word all-ones (0xFFFFFFFF)': (high: 0, low: 0xFFFFFFFF),
      'high word set, low zero (0x100000000)': (high: 1, low: 0),
      'distinct bytes in both words': (high: 0x123456, low: 0x789ABC),
    };

    cases.forEach((name, pair) {
      test('combines and splits back exactly: $name', () {
        final combined = combineUint32Pair(pair.high, pair.low);
        final split = splitUint32Pair(combined);
        expect(split.high, pair.high, reason: 'high word for $name');
        expect(split.low, pair.low, reason: 'low word for $name');
      });
    });

    test('combineUint32Pair produces the expected magnitude', () {
      expect(combineUint32Pair(0, 0), 0);
      expect(combineUint32Pair(0, 1), 1);
      expect(combineUint32Pair(0, 0xFFFFFFFF), 0xFFFFFFFF);
      expect(combineUint32Pair(1, 0), 0x100000000);
      // 0x123456 * 2^32 + 0x789ABC, spelled out arithmetically rather than
      // as one wide literal.
      expect(
        combineUint32Pair(0x123456, 0x789ABC),
        0x123456 * 0x100000000 + 0x789ABC,
      );
    });

    test(
        'rejects a value that needs more than 53 bits, on platforms where '
        'int cannot represent it exactly', () {
      if (!kIntIsImprecise) {
        return; // Exact on the VM; see int_vm_uint64_boundary_test.dart.
      }
      // high = 0x300000 alone already needs 54 bits once combined with any
      // low word, so this must throw rather than silently round.
      expect(() => combineUint32Pair(0x300000, 0), throwsUnsupportedError);
      expect(
        () => splitUint32Pair(0x300000 * 0x100000000),
        throwsUnsupportedError,
      );
    });
  });

  group('Uint64ByteData round-trips through ByteData', () {
    // Same safe-magnitude values as above, plus the exact combined int for
    // the "distinct bytes" case.
    final values = <String, int>{
      'zero': 0,
      'one': 1,
      '0xFFFFFFFF': 0xFFFFFFFF,
      '0x100000000': 0x100000000,
      'distinct bytes in both words': combineUint32Pair(0x123456, 0x789ABC),
    };

    values.forEach((name, value) {
      test('write then read (big-endian): $name', () {
        final data = ByteData(8);
        data.setUint64Split(0, value);
        expect(data.getUint64Split(0), value);
      });

      test('write then read (little-endian): $name', () {
        final data = ByteData(8);
        data.setUint64Split(0, value, Endian.little);
        expect(data.getUint64Split(0, Endian.little), value);
      });

      test('matches word-by-word getUint32/setUint32 (big-endian): $name', () {
        final data = ByteData(8);
        data.setUint64Split(0, value);
        final pair = splitUint32Pair(value);
        expect(data.getUint32(0), pair.high);
        expect(data.getUint32(4), pair.low);
      });
    });

    test('big-endian and little-endian encodings differ for a mixed value', () {
      final value = combineUint32Pair(0x123456, 0x789ABC);
      final big = ByteData(8)..setUint64Split(0, value);
      final little = ByteData(8)..setUint64Split(0, value, Endian.little);
      expect(
        big.buffer.asUint8List(),
        isNot(equals(little.buffer.asUint8List())),
      );
      expect(little.getUint64Split(0, Endian.little), value);
    });

    test('offset is honored', () {
      final value = combineUint32Pair(0x123456, 0x789ABC);
      final data = ByteData(12);
      data.setUint64Split(4, value);
      expect(data.getUint64Split(4), value);
      // Bytes before the offset are untouched.
      expect(data.getUint32(0), 0);
    });
  });

  group('ByteData.addToUint64Split', () {
    test('adds without carry', () {
      final data = ByteData(8)..setUint64Split(0, 10);
      data.addToUint64Split(0, 5);
      expect(data.getUint64Split(0), 15);
    });

    test('carries from the low word into the high word', () {
      final data = ByteData(8)..setUint64Split(0, 0xFFFFFFFF);
      data.addToUint64Split(0, 1);
      expect(data.getUint32(0), 1);
      expect(data.getUint32(4), 0);
    });

    test(
        'is exact when the high word is already set (AES-GCM style nonce), '
        'without ever combining the 64-bit value into a single int', () {
      // The AES-GCM invocation counter (RFC 5647) is derived from key
      // material, so its top bit is routinely set -- checked word-by-word
      // here (rather than via getUint64Split) because combining a value
      // this large into one int is exactly what addToUint64Split is built
      // to avoid needing.
      final data = ByteData(8)
        ..setUint32(0, 0x80000000)
        ..setUint32(4, 0xFFFFFFFF);
      data.addToUint64Split(0, 1);
      expect(data.getUint32(0), 0x80000001);
      expect(data.getUint32(4), 0x00000000);
    });

    test('wraps the high word too, at the top of the 64-bit range', () {
      final data = ByteData(8)
        ..setUint32(0, 0xFFFFFFFF)
        ..setUint32(4, 0xFFFFFFFF);
      data.addToUint64Split(0, 1);
      // Wraps modulo 2^64, matching unsigned counter-overflow semantics.
      expect(data.getUint32(0), 0);
      expect(data.getUint32(4), 0);
    });

    test('wraps the low word repeatedly across several additions', () {
      final data = ByteData(8)..setUint64Split(0, 0xFFFFFFFE);
      for (var sequence = 0; sequence < 4; sequence++) {
        data.addToUint64Split(0, 1);
      }
      expect(data.getUint64Split(0), 0x100000002);
    });

    test('honors byteOffset', () {
      final data = ByteData(12)..setUint64Split(4, 1);
      data.addToUint64Split(4, 41);
      expect(data.getUint64Split(4), 42);
    });
  });

  group('IntX.toUint64', () {
    test('round-trips through ByteData.getUint64Split', () {
      final value = combineUint32Pair(0x123456, 0x789ABC);
      final bytes = value.toUint64();
      expect(ByteData.sublistView(bytes).getUint64Split(0), value);
    });

    test('matches the big-endian byte layout for small values', () {
      final bytes = 42.toUint64();
      expect(bytes, [0, 0, 0, 0, 0, 0, 0, 42]);
    });

    test(
        'matches the big-endian byte layout word-by-word for a value with '
        'distinct bytes in both words', () {
      final value = combineUint32Pair(0x123456, 0x789ABC);
      final bytes = value.toUint64();
      expect(
        bytes,
        [0x00, 0x12, 0x34, 0x56, 0x00, 0x78, 0x9A, 0xBC],
      );
    });
  });
}
