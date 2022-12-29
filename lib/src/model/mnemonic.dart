import 'dart:typed_data';

import 'package:convert/convert.dart';
import 'package:dart_crypto/dart_crypto.dart';

class Mnemonic {
  final String keywords;
  final Uint8List seed;
  final ExtendedKey rootKeyPair;

  Mnemonic(this.keywords, this.seed, this.rootKeyPair);

  factory Mnemonic.fromWordCount({wordCount = 12, curve = 'secp256k1'}) {
    final randomMnemonic =
        MnemonicHelper.generateMnemonicKeywords(wordCount: wordCount);
    final seed = MnemonicHelper.mnemonicToSeed(randomMnemonic);
    final rootKeyPair = ExtendedKey.fromSeed(seed, curve: curve);
    return Mnemonic(randomMnemonic, seed, rootKeyPair);
  }

  factory Mnemonic.fromMnemonic(String mnemonic, {curve = 'secp256k1'}) {
    final seed = MnemonicHelper.mnemonicToSeed(mnemonic);
    final rootKeyPair = ExtendedKey.fromSeed(seed, curve: curve);
    return Mnemonic(mnemonic, seed, rootKeyPair);
  }

  ExtendedKey createAccount(int index, {chainId = 0}) {
    return rootKeyPair
        .derivePrivateChildKeyFromPath("m/44'/$chainId'/$index'/0");
  }

  @override
  String toString() {
    return 'Keywords: $keywords\n seed: ${hex.encode(seed)}\n rootPrivateKey: ${rootKeyPair.toBase58String()}';
  }
}
