import 'dart:convert';
import 'dart:typed_data';

import 'package:convert/convert.dart';
import 'package:dartssh2/dartssh2.dart';
import 'package:dartssh2/src/hostkey/hostkey_ecdsa.dart';
import 'package:dartssh2/src/hostkey/hostkey_ed25519.dart';
import 'package:dartssh2/src/hostkey/hostkey_rsa.dart';
import 'package:dartssh2/src/ssh_hostkey.dart';
import 'package:dartssh2/src/utils/int.dart';
import 'package:dartssh2/src/utils/bigint.dart';
import 'package:dartssh2/src/utils/list.dart';
import 'package:dartssh2/src/utils/utf8.dart';

part 'msg_channel.dart';
part 'msg_debug.dart';
part 'msg_disconnect.dart';
part 'msg_ignore.dart';
part 'msg_kex_dh.dart';
part 'msg_kex_ecdh.dart';
part 'msg_kex.dart';
part 'msg_request.dart';
part 'msg_service.dart';
part 'msg_userauth.dart';

sealed class SSHMessage {
  Uint8List encode();

  static int readMessageId(Uint8List bytes) {
    return bytes[0];
  }

  // RFC 4251 Section 7: Message number validation
  static bool isValidMessageId(int messageId) {
    return messageId >= 1 && messageId <= 255;
  }

  static bool isTransportMessage(int messageId) {
    return (messageId >= 1 && messageId <= 19) || // Generic
        (messageId >= 20 && messageId <= 29) || // Algorithm negotiation
        (messageId >= 30 && messageId <= 49); // Key exchange
  }

  static bool isUserAuthMessage(int messageId) {
    return (messageId >= 50 && messageId <= 59) || // Generic
        (messageId >= 60 && messageId <= 79); // Method specific
  }

  static bool isConnectionMessage(int messageId) {
    return (messageId >= 80 && messageId <= 89) || // Generic
        (messageId >= 90 && messageId <= 127); // Channel related
  }
}

class SSHMessageReader {
  /// Message data.
  final Uint8List data;

  SSHMessageReader(this.data) : _byteData = ByteData.sublistView(data);

  /// ByteData view of [data], used for reading numbers.
  final ByteData _byteData;

  /// The current position in the message.
  var _offset = 0;

  bool get isDone => _offset >= data.length;

  void skip(int bytes) {
    _offset += bytes;
  }

  bool readBool() {
    return readUint8() != 0;
  }

  int readUint8() {
    return _byteData.getUint8(_offset++);
  }

  int readUint16() {
    final value = _byteData.getUint16(_offset);
    _offset += 2;
    return value;
  }

  int readUint32() {
    final value = _byteData.getUint32(_offset);
    _offset += 4;
    return value;
  }

  int readUint64() {
    final value = _byteData.getUint64(_offset);
    _offset += 8;
    return value;
  }

  Uint8List readBytes(int length) {
    final value = Uint8List.view(_byteData.buffer, _offset, length);
    _offset += length;
    return value;
  }

  Uint8List readString() {
    final length = readUint32();
    final value = Uint8List.sublistView(data, _offset, _offset + length);
    _offset += length;
    return value;
  }

  String readUtf8() {
    return utf8.decode(readString());
  }

  List<String> readNameList() {
    final string = utf8.decode(readString());
    final list = string.split(',');
    return list;
  }

  List<Uint8List> readStringList() {
    final list = <Uint8List>[];
    while (!isDone) {
      list.add(readString());
    }
    return list;
  }

  BigInt readMpint() {
    final magnitude = readString();
    final value = decodeBigIntWithSign(1, magnitude);
    return value;
  }

  Uint8List readToEnd() {
    final value = Uint8List.sublistView(data, _offset);
    _offset = data.length;
    return value;
  }
}

class SSHMessageWriter {
  SSHMessageWriter({bool copy = false}) : _builder = BytesBuilder(copy: copy);

  final BytesBuilder _builder;

  int get length => _builder.length;

  void writeBool(bool value) {
    // RFC 4251: applications MUST NOT store values other than 0 and 1
    _builder.addByte(value ? 1 : 0);
  }

  void writeUint8(int value) {
    _builder.addByte(value);
  }

  // void writeUint16(int value) {
  //   _builder.addByte(value >> 8);
  //   _builder.addByte(value);
  // }

  void writeUint32(int value) {
    _builder.add(value.toUint32());
  }

  void writeUint64(int value) {
    _builder.add(value.toUint64());
  }

  /// Write fixed length string.
  void writeBytes(Uint8List value) {
    _builder.add(value);
  }

  /// Write variable length string.
  void writeString(Uint8List value) {
    writeUint32(value.length);
    writeBytes(value);
  }

  void writeUtf8(String value) {
    writeString(utf8Encode(value));
  }

  /// Write comma separated list of names as a string.
  void writeNameList(List<String> value) {
    // RFC 4251: A name MUST have a non-zero length, and it MUST NOT contain a comma
    for (final name in value) {
      if (name.isEmpty) {
        throw ArgumentError('Name in name-list cannot be empty');
      }
      if (name.contains(',')) {
        throw ArgumentError('Name in name-list cannot contain comma: $name');
      }
      // Names must be US-ASCII
      if (!_isUsAscii(name)) {
        throw ArgumentError('Name in name-list must be US-ASCII: $name');
      }
    }
    writeString(Utf8Encoder().convert(value.join(',')));
  }

  bool _isUsAscii(String str) {
    for (int i = 0; i < str.length; i++) {
      if (str.codeUnitAt(i) > 127) return false;
    }
    return true;
  }

  /// Write multiple precision integer as a string.
  void writeMpint(BigInt value) {
    writeString(encodeBigInt(value));
  }

  Uint8List takeBytes() {
    return _builder.takeBytes();
  }
}
