import 'dart:math';
import 'dart:typed_data';

class CryptoUtils {
  static BigInt readBytes(Uint8List bytes) {
    BigInt result = BigInt.zero;

    for (final byte in bytes) {
      // reading in big-endian, so we essentially concat the new byte to the end
      result = (result << 8) | BigInt.from(byte & 0xff);
    }
    return result;
  }

  static Uint8List writeBigInt(BigInt number) {
    int needsPaddingByte;
    int rawSize;
    final negativeFlag = BigInt.from(0x80);

    if (number > BigInt.zero) {
      rawSize = (number.bitLength / 8).ceil();
      needsPaddingByte =
          ((number >> (rawSize - 1) * 8) & negativeFlag) == negativeFlag
              ? 1
              : 0;

      if (rawSize < 32) {
        needsPaddingByte = 1;
      }
    } else {
      needsPaddingByte = 0;
      rawSize = (number.bitLength + 8) >> 3;
    }

    final size = rawSize < 32 ? rawSize + needsPaddingByte : rawSize;
    var result = Uint8List(size);
    var byteMask = BigInt.from(0xff);
    for (int i = 0; i < size; i++) {
      result[size - i - 1] = (number & byteMask).toInt();
      number = number >> 8;
    }
    return result;
  }

  static Uint8List generateRandomBytes(int size) {
    final rng = Random.secure();
    final bytes = Uint8List(size);
    for (var i = 0; i < size; i++) {
      bytes[i] = rng.nextInt(8);
    }
    return bytes;
  }
}
