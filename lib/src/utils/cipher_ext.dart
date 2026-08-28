import 'dart:typed_data';

import 'package:dartssh2/src/algorithm/ssh_crypto_backend.dart';
import 'package:pointycastle/pointycastle.dart';

extension BlockCipherX on BlockCipher {
  Uint8List processAll(Uint8List data) {
    if (data.length % blockSize != 0) {
      throw FormatException('input ${data.length} not multiple of $blockSize');
    }

    // A cipher that can take the whole packet is given the whole packet. The
    // loop below is the cheapest thing to do for an implementation in this
    // isolate and the most expensive one for a backend that pays per call —
    // see [SSHBulkBlockCipher].
    final self = this;
    if (self is SSHBulkBlockCipher) return self.processBulk(data);

    final result = Uint8List(data.length);

    for (var offset = 0; offset < data.length; offset += blockSize) {
      processBlock(data, offset, result, offset);
    }

    return result;
  }
}

extension AEADCipherX on AEADCipher {
  Uint8List processAll(Uint8List data) {
    final cipher = this as dynamic;
    return cipher.process(data) as Uint8List;
  }
}

extension MacX on Mac {
  void updateAll(Uint8List data) {
    update(data, 0, data.length);
  }

  Uint8List finish() {
    final result = Uint8List(macSize);
    final resuitLength = doFinal(result, 0);
    if (resuitLength != macSize) throw FormatException('mac size mismatch');
    return result;
  }
}
