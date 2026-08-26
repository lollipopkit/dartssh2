import 'dart:typed_data';

import 'package:dartssh2/src/ssh_errors.dart';
import 'package:dartssh2/src/ssh_message.dart';
import 'package:test/test.dart';

/// Writes [value] as an mpint and returns the raw encoded bytes (including
/// the 4-byte length prefix).
Uint8List _encodeMpint(BigInt value) {
  final writer = SSHMessageWriter();
  writer.writeMpint(value);
  return writer.takeBytes();
}

/// Reads an mpint back out of [bytes], which must be exactly one encoded
/// mpint (length prefix + payload) with nothing else following.
BigInt _decodeMpint(List<int> bytes) {
  final reader = SSHMessageReader(Uint8List.fromList(bytes));
  return reader.readMpint();
}

void main() {
  group('SSHMessageWriter/Reader mpint (RFC 4251 §5)', () {
    // Each vector is (value, expected wire bytes including the 4-byte
    // length prefix), taken from RFC 4251 §5's own examples plus the zero
    // case that the RFC specifies but does not enumerate alongside them.
    //
    // Only the encoding side covers the negative vectors. readMpint always
    // decodes as non-negative on purpose: SSH never puts a negative mpint on
    // the wire, and inferring the sign would break peers that omit the
    // leading 0x00 padding. See the comment on readMpint.
    final vectors = <BigInt, List<int>>{
      BigInt.zero: [0x00, 0x00, 0x00, 0x00],
      BigInt.parse('9a378f9b2e332a7', radix: 16): [
        0x00, 0x00, 0x00, 0x08, //
        0x09, 0xa3, 0x78, 0xf9, 0xb2, 0xe3, 0x32, 0xa7,
      ],
      BigInt.parse('80', radix: 16): [
        0x00, 0x00, 0x00, 0x02, //
        0x00, 0x80,
      ],
      BigInt.from(-0x1234): [
        0x00, 0x00, 0x00, 0x02, //
        0xed, 0xcc,
      ],
      BigInt.parse('-deadbeef', radix: 16): [
        0x00, 0x00, 0x00, 0x05, //
        0xff, 0x21, 0x52, 0x41, 0x11,
      ],
    };

    vectors.forEach((value, expected) {
      test('encodes $value to the RFC 4251 wire bytes', () {
        expect(_encodeMpint(value), expected);
      });

      if (!value.isNegative) {
        test('decodes the RFC 4251 wire bytes back to $value', () {
          expect(_decodeMpint(expected), value);
        });
      }
    });

    test('round-trips the non-negative values SSH actually puts on the wire',
        () {
      final samples = <BigInt>[
        BigInt.zero,
        BigInt.one,
        BigInt.from(127),
        BigInt.from(128),
        BigInt.parse('9' * 60),
        BigInt.parse('ff112233445566778899', radix: 16),
      ];

      for (final value in samples) {
        expect(_decodeMpint(_encodeMpint(value)), value, reason: '$value');
      }
    });

    test('decodes a negative-looking mpint as non-negative', () {
      // Deliberate: a peer that omits the leading 0x00 padding must keep
      // working. RFC 4251's -0x1234 vector therefore reads back as 0xedcc.
      expect(
        _decodeMpint([0x00, 0x00, 0x00, 0x02, 0xed, 0xcc]),
        BigInt.from(0xedcc),
      );
    });

    test('zero is encoded with a zero-length payload, not a single 0 byte', () {
      // This is the specific defect from the audit: encodeBigInt alone
      // returns a single 0x00 byte (ASN.1/DER style), but RFC 4251 mpint
      // requires a zero-length string for zero.
      expect(_encodeMpint(BigInt.zero), [0x00, 0x00, 0x00, 0x00]);
    });
  });

  group('SSHMessageReader.readNameList (RFC 4251 §5)', () {
    test('decodes an empty name-list to an empty list, not [""]', () {
      final reader = SSHMessageReader(
        Uint8List.fromList([0x00, 0x00, 0x00, 0x00]),
      );

      expect(reader.readNameList(), isEmpty);
    });

    test('decodes a single-name list', () {
      final writer = SSHMessageWriter();
      writer.writeNameList(['zlib']);
      final reader = SSHMessageReader(writer.takeBytes());

      expect(reader.readNameList(), ['zlib']);
    });

    test('decodes a multi-name list', () {
      final writer = SSHMessageWriter();
      writer.writeNameList(['diffie-hellman-group14-sha256', 'zlib', 'none']);
      final reader = SSHMessageReader(writer.takeBytes());

      expect(
        reader.readNameList(),
        ['diffie-hellman-group14-sha256', 'zlib', 'none'],
      );
    });

    test('writeNameList round-trips an empty list to a zero-length string', () {
      final writer = SSHMessageWriter();
      writer.writeNameList(const []);

      expect(writer.takeBytes(), [0x00, 0x00, 0x00, 0x00]);
    });
  });

  group('SSHMessage.readMessageId', () {
    test('reads the first byte', () {
      expect(SSHMessage.readMessageId(Uint8List.fromList([42, 1, 2])), 42);
    });

    test('throws SSHPacketError on an empty payload instead of RangeError', () {
      expect(
        () => SSHMessage.readMessageId(Uint8List(0)),
        throwsA(isA<SSHPacketError>()),
      );
    });
  });
}
