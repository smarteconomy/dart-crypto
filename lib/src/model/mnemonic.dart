import 'dart:typed_data';

import 'package:convert/convert.dart';
import 'package:dart_crypto/dart_crypto.dart';

class MnemonicWallet {
  final String keywords;
  final Uint8List seed;
  final ExtendedKey rootKeyPair;

  MnemonicWallet(this.keywords, this.seed, this.rootKeyPair);

  factory MnemonicWallet.fromWordCount({wordCount = 12, curve = 'secp256k1'}) {
    final randomMnemonic =
        MnemonicHelper.generateMnemonicKeywords(wordCount: wordCount);
    final seed = MnemonicHelper.mnemonicToSeed(randomMnemonic);
    final rootKeyPair = ExtendedKey.fromSeed(seed, curve: curve);
    return MnemonicWallet(randomMnemonic, seed, rootKeyPair);
  }

  factory MnemonicWallet.fromMnemonic(String mnemonic, {curve = 'secp256k1'}) {
    final seed = MnemonicHelper.mnemonicToSeed(mnemonic);
    final rootKeyPair = ExtendedKey.fromSeed(seed, curve: curve);
    return MnemonicWallet(mnemonic, seed, rootKeyPair);
  }

  ExtendedKey createAccountKey(int index,
      {chainId = 0, external = true, addressIndex = 0}) {
    return rootKeyPair.deriveChildKeyFromPath(
        "m/44'/$chainId'/$index'/${external ? 0 : 1}/$addressIndex");
  }

  @override
  String toString() {
    return 'Keywords: $keywords\n seed: ${hex.encode(seed)}\n rootPrivateKey: ${rootKeyPair.toBase58String()}';
  }
}
