import 'dart:typed_data';

import 'package:pointycastle/macs/hmac.dart';

/// Custom HMac implementation that truncates output to a configurable size.
/// The truncation size is controlled by the [_truncatedSize] constructor parameter.
class TruncatedHMac extends HMac {
  final int _truncatedSize;

  TruncatedHMac(super.digest, super.blockSize, this._truncatedSize);

  @override
  int get macSize => _truncatedSize;

  @override
  int doFinal(Uint8List out, int outOff) {
    // Call the original doFinal to get the full MAC
    final fullMacSize = super.macSize;
    final tempBuffer = Uint8List(fullMacSize);
    super.doFinal(tempBuffer, 0);

    // Copy only the first 12 bytes to the output
    out.setRange(outOff, outOff + _truncatedSize, tempBuffer);

    return _truncatedSize;
  }
}
