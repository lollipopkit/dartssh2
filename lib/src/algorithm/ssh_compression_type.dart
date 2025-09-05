import 'dart:typed_data';
import 'dart:io';

import 'package:dartssh2/src/ssh_algorithm.dart';

class SSHCompressionType with SSHAlgorithm {
  static const values = [
    none,
    zlib,
  ];

  static const none = SSHCompressionType._(
    name: 'none',
    compressor: null,
    decompressor: null,
  );

  static const zlib = SSHCompressionType._(
    name: 'zlib',
    compressor: _zlibCompressor,
    decompressor: _zlibDecompressor,
  );

  @override
  final String name;

  final Uint8List Function(Uint8List)? compressor;
  final Uint8List Function(Uint8List)? decompressor;

  const SSHCompressionType._({
    required this.name,
    required this.compressor,
    required this.decompressor,
  });

  bool get isNone => compressor == null && decompressor == null;

  Uint8List compress(Uint8List data) {
    if (compressor == null) return data;
    return compressor!(data);
  }

  Uint8List decompress(Uint8List data) {
    if (decompressor == null) return data;
    return decompressor!(data);
  }

  static Uint8List _zlibCompressor(Uint8List data) {
    final codec = ZLibCodec();
    return Uint8List.fromList(codec.encode(data));
  }

  static Uint8List _zlibDecompressor(Uint8List data) {
    final codec = ZLibCodec();
    return Uint8List.fromList(codec.decode(data));
  }
}