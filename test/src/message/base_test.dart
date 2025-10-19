import 'dart:convert';
import 'dart:typed_data';

import 'package:dartssh2/src/message/base.dart';
import 'package:test/test.dart';

void main() {
  Uint8List encodeNameList(String raw) {
    final bytes = utf8.encode(raw);
    final length = ByteData(4)..setUint32(0, bytes.length);
    final builder = BytesBuilder();
    builder.add(Uint8List.view(length.buffer));
    builder.add(bytes);
    return builder.takeBytes();
  }

  test('readNameList returns empty list for empty name-list', () {
    final reader = SSHMessageReader(encodeNameList(''));
    expect(reader.readNameList(), isEmpty);
  });

  test('readNameList parses comma-separated ASCII names', () {
    final reader = SSHMessageReader(encodeNameList('algo1,algo2'));
    expect(reader.readNameList(), ['algo1', 'algo2']);
  });

  test('readNameList rejects empty names', () {
    final reader = SSHMessageReader(encodeNameList('algo1,,algo2'));
    expect(() => reader.readNameList(), throwsFormatException);
  });

  test('readNameList rejects non-ASCII names', () {
    final reader = SSHMessageReader(encodeNameList('algö'));
    expect(() => reader.readNameList(), throwsFormatException);
  });
}
