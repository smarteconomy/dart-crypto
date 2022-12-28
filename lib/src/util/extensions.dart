import 'dart:typed_data';

import 'package:bs58check/bs58check.dart' as bs58check;
import 'package:convert/convert.dart';
import 'package:dart_crypto/src/util/crypto_utils.dart';
import 'package:pointycastle/pointycastle.dart';

extension PrivateKeyExtension on ECPrivateKey {
  String toWIF({compressed = true, prefix = 0x80}) {
    final compressedOffset = compressed ? 1 : 0;
    const prefixLength = 33;
    var buffer = Uint8List(prefixLength + compressedOffset);
    buffer[0] = prefix;
    buffer.setRange(1, prefixLength, CryptoUtils.writeBigInt(d!));
    if (compressed) {
      buffer[prefixLength] = 0x01;
    }
    return bs58check.encode(buffer);
  }

  ECPublicKey toPublicKey() {
    final Q = parameters!.G * d;
    return ECPublicKey(Q, parameters);
  }
}

extension Uint8ListExtension on Uint8List {
  String toBinaryString() {
    return map((byte) => byte.toRadixString(2).padLeft(8, '0')).join('');
  }

  String toHexString() {
    return map((byte) => byte.toRadixString(16).padLeft(2, '0')).join('');
  }
}

extension StringExtensions on String {
  int fromBinaryString() {
    return int.parse(this, radix: 2);
  }

  Uint8List hexToBytes() {
    return Uint8List.fromList(hex.decode(this));
  }
}

extension IntExtensions on int {
  String toBinaryString() {
    return toRadixString(2);
  }
}
