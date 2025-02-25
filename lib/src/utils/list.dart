import 'dart:math';

import 'dart:typed_data';

import 'package:pointycastle/api.dart' show KeyParameter;
import 'package:pointycastle/random/fortuna_random.dart';

final secureRandom = _createSecureRandom();

FortunaRandom _createSecureRandom() {
  final secureRandom = FortunaRandom();
  final seedSource = Random.secure();
  final seeds = Uint8List(32);
  for (var i = 0; i < 32; i++) {
    seeds[i] = seedSource.nextInt(256);
  }
  secureRandom.seed(KeyParameter(seeds));
  return secureRandom;
}

Uint8List randomBytes(int length) {
  final bytes = Uint8List(length);
  for (var i = 0; i < length; i++) {
    bytes[i] = secureRandom.nextUint8();
  }
  return bytes;
}

extension ListX<T> on List<T> {
  bool equals(List<T> other) {
    if (other.length != length) return false;
    for (int i = 0; i < length; i++) {
      if (this[i] != other[i]) return false;
    }
    return true;
  }
}
