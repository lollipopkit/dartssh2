// The Dart VM full-64-bit-range companion to int_test.dart.
//
// These cases use integer literals above 2^53 (some above 2^63) that
// dart2js refuses to even compile ("The integer literal ... can't be
// represented exactly in JavaScript"), so this file is VM-only. See
// int_test.dart for the web-safe coverage of the same helpers.
@TestOn('vm')
library;

import 'dart:typed_data';

import 'package:dartssh2/src/utils/int.dart';
import 'package:test/test.dart';

void main() {
  test('kIntIsImprecise is false on the VM', () {
    expect(kIntIsImprecise, isFalse);
  });

  group(
      'combineUint32Pair / splitUint32Pair are exact across the full '
      '64-bit range', () {
    final cases = <String, Uint32Pair>{
      'top bit set, otherwise zero (2^63)': (high: 0x80000000, low: 0),
      'all bits set (2^64 - 1)': (high: 0xFFFFFFFF, low: 0xFFFFFFFF),
      'high word with only the top bit set, distinct low word': (
        high: 0x80000000,
        low: 0x0BADF00D
      ),
      'just above 2^53 (not representable on the web)': (
        high: 0x200000,
        low: 1
      ),
    };

    cases.forEach((name, pair) {
      test('combines and splits back exactly: $name', () {
        final combined = combineUint32Pair(pair.high, pair.low);
        final split = splitUint32Pair(combined);
        expect(split.high, pair.high, reason: 'high word for $name');
        expect(split.low, pair.low, reason: 'low word for $name');
      });
    });

    test(
        'reproduces ByteData.getUint64/setUint64 bit-for-bit, including '
        'negative (top-bit-set) values', () {
      // ByteData.getUint64 returns a *negative* int for values with bit 63
      // set, because the VM's int is a real 64-bit two's complement
      // integer. combineUint32Pair must match that exactly, not "fix" it.
      final referenceData = ByteData(8);
      final splitData = ByteData(8);

      for (final pair in [
        (high: 0x80000000, low: 0),
        (high: 0xFFFFFFFF, low: 0xFFFFFFFF),
        (high: 0xFFFFFFFF, low: 0),
        (high: 0x80000001, low: 0x00000002),
      ]) {
        referenceData
          ..setUint32(0, pair.high)
          ..setUint32(4, pair.low);
        final expected = referenceData.getUint64(0);
        expect(expected, lessThan(0), reason: 'sanity: top bit is set');

        final actual = combineUint32Pair(pair.high, pair.low);
        expect(actual, expected);

        // And the inverse: setUint64Split from that same negative int must
        // write the identical bytes setUint64 would have.
        splitData.setUint64Split(0, expected);
        expect(
          splitData.buffer.asUint8List(),
          referenceData.buffer.asUint8List(),
        );
      }
    });
  });

  group('ByteData.getUint64Split / setUint64Split match getUint64/setUint64',
      () {
    test('for a battery of values spanning the 64-bit range', () {
      final values = <int>[
        0,
        1,
        0xFFFFFFFF,
        0x100000000,
        0x0102030405060708,
        9223372036854775807, // 2^63 - 1, the largest positive VM int.
        -1, // all bits set, i.e. 2^64 - 1 unsigned.
        -9223372036854775808, // 2^63, the smallest (most negative) VM int.
      ];

      for (final value in values) {
        final reference = ByteData(8)..setUint64(0, value);
        final split = ByteData(8)..setUint64Split(0, value);
        expect(
          split.buffer.asUint8List(),
          reference.buffer.asUint8List(),
          reason: 'setUint64Split($value)',
        );
        expect(
          split.getUint64Split(0),
          reference.getUint64(0),
          reason: 'getUint64Split for $value',
        );
      }
    });
  });
}
