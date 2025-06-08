import 'dart:typed_data';

import 'package:dartssh2/src/ssh_errors.dart' show SSHStateError;

/// SSH packet sequence number wraps around to zero after every 2^32
/// packets. According to RFC4253, this counter should never be reset,
/// even during key re-exchanges.
abstract class SSHPacket {
  /// The maximum size of a packet including the header and MAC.
  static const maxLength = 35000;

  /// The maximum size of uncompressed packet payload.
  static const maxPayloadLength = 32768;

  /// rfc4253 requires the total length of the packet is a multiple of 8 or
  /// the cipher block size, whichever is larger.
  static const minAlign = 8;

  /// The length of the packet header, is the sum of the lengths of the
  /// length field and the padding length field.
  static const headerLength = 5;

  /// Returns the length field of the packet. This is the number of bytes
  /// following the length field except for the MAC. [packet] can be partial.
  static int readPacketLength(Uint8List packet) {
    return ByteData.sublistView(packet).getUint32(0);
  }

  /// Returns the length of padding at the end of the packet before the MAC.
  /// [packet] can be partial.
  static int readPaddingLength(Uint8List packet) {
    return ByteData.sublistView(packet).getUint8(4);
  }

  /// Computes the correct padding length for the packet from [payloadLength]
  /// and [align].
  static int paddingLength(int payloadLength, {required int align}) {
    final paddingLength = align - ((payloadLength + headerLength) % align);
    // ssh padding must be at least 4 bytes
    return paddingLength < 4 ? paddingLength + align : paddingLength;
  }

  /// Returns a rfc4253 packet built from [payload] and [align] including the
  /// length field, padding length field, and padding. Withouth the MAC.
  static Uint8List pack(Uint8List payload, {required int align}) {
    final padding = paddingLength(payload.length, align: align);
    final header = ByteData(5);
    header.setUint32(0, 1 + payload.length + padding);
    header.setUint8(4, padding);
    final result = BytesBuilder(copy: false);
    result.add(Uint8List.view(header.buffer));
    result.add(payload);
    result.add(Uint8List(padding));
    return result.takeBytes();
  }
}

/// SSH packet sequence number wraps around to zero after every 2^32
/// packets.
class SSHPacketSN {
  SSHPacketSN(this._value);

  SSHPacketSN.fromZero() : _value = 0;

  var _value = 0;

  int get value => _value;

  // RFC 4251 Section 9.3.3: peers MUST rekey before sequence number wrap
  bool get needsRekey => _value > 0xF0000000; // Trigger rekey before wrap

  void increase() {
    if (_value == 0xffffffff) {
      // RFC 4251: This should never happen - must rekey before wrap
      throw SSHStateError('Sequence number wrapped - connection must be rekeyed');
    } else {
      _value++;
    }
  }
}
