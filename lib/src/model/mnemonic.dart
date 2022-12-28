import 'dart:typed_data';

import 'package:convert/convert.dart';
import 'package:dart_crypto/dart_crypto.dart';

class Mnemonic {
  final String keywords;
  final Uint8List seed;
  final ExtendedKeyPair rootKeyPair;

  Mnemonic(this.keywords, this.seed, this.rootKeyPair);

  factory Mnemonic.fromWordCount({wordCount = 12}) {
    final randomMnemonic =
        MnemonicHelper.generateMnemonicKeywords(wordCount: wordCount);
    final seed = MnemonicHelper.mnemonicToSeed(randomMnemonic);
    final rootKeyPair = ExtendedKeyPair.fromSeed(seed);
    return Mnemonic(randomMnemonic, seed, rootKeyPair);
  }

  factory Mnemonic.fromMnemonic(String mnemonic) {
    final seed = MnemonicHelper.mnemonicToSeed(mnemonic);
    final rootKeyPair = ExtendedKeyPair.fromSeed(seed);
    return Mnemonic(mnemonic, seed, rootKeyPair);
  }

  @override
  String toString() {
    return 'Keywords: $keywords\n seed: ${hex.encode(seed)}\n rootPrivateKey: ${rootKeyPair.toBase58String()} \n rootPublicKey: ${rootKeyPair.toBase58String(neutered: true)}}';
  }
}
