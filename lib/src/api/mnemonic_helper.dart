import 'dart:convert';
import 'dart:typed_data';
import 'package:dart_crypto/src/util/extensions.dart';
import 'package:dart_crypto/src/util/crypto_utils.dart';
import 'package:pointycastle/export.dart';
import '../assets/bip39_wordlist_en.dart';

class MnemonicHelper {
  static String generateMnemonicKeywords({wordCount = 12}) {
    if (wordCount % 3 != 0) throw ArgumentError("Invalid Mnemonic Size ");
    final strength = (wordCount * 11) - (wordCount ~/ 3);
    final entropySize = strength ~/ 8;
    final randomEntropy = CryptoUtils.generateRandomBytes(entropySize);
    final mnemonic = entropyToMnemonic(randomEntropy);
    return mnemonic;
  }

  static Uint8List mnemonicToSeed(String mnemonic, [String passphrase = ""]) {
    final rootString = Uint8List.fromList(utf8.encode('mnemonic$passphrase'));
    final keyDerivator = KeyDerivator("SHA-512/HMAC/PBKDF2");
    keyDerivator.init(Pbkdf2Parameters(rootString, 2048, 64));
    return keyDerivator.process(Uint8List.fromList(mnemonic.codeUnits));
  }

  static bool checkMnemonic(String mnemonic) {
    bool isValid = false;
    try {
      isValid = mnemonicToEntropy(mnemonic).isNotEmpty;
    } catch (e) {
      isValid = false;
    }

    return isValid;
  }

  static String entropyToMnemonic(Uint8List randomBytes) {
    if (randomBytes.length < 16 ||
        randomBytes.length > 32 ||
        randomBytes.length % 4 != 0) {
      throw StateError('Invalid Entropy');
    }

    final entropyBits = randomBytes.toBinaryString();
    final checksumBits = _calculateEntropyChecksum(randomBytes);
    final bits = entropyBits + checksumBits;
    final regex = RegExp(r".{1,11}", caseSensitive: false, multiLine: false);
    final chunks = regex
        .allMatches(bits)
        .map((match) => match.group(0)!)
        .toList(growable: false);

    String words =
        chunks.map((binary) => wordList[binary.fromBinaryString()]).join(' ');
    return words;
  }

  static Uint8List mnemonicToEntropy(mnemonic) {
    var words = mnemonic.split(' ');

    if (words.length % 3 != 0) throw ArgumentError("Invalid Mnemonic");

    // convert word indices to 11 bit binary strings
    final bits = words.map((word) {
      final index = wordList.indexOf(word);
      if (index == -1) throw ArgumentError("Invalid Mnemonic");
      return index.toBinaryString().padLeft(11, '0');
    }).join('');

    // split the binary string into Entropy and Checksum
    final dividerIndex = (bits.length / 33).floor() * 32;
    final entropyBits = bits.substring(0, dividerIndex);
    final checksumBits = bits.substring(dividerIndex);

    // calculate the checksum and compare
    final regex = RegExp(r".{1,8}");
    final entropyBytes = Uint8List.fromList(regex
        .allMatches(entropyBits)
        .map((match) => match.group(0)!.fromBinaryString())
        .toList(growable: false));

    if (entropyBytes.length < 16 ||
        entropyBytes.length > 32 ||
        entropyBytes.length % 4 != 0) throw StateError('Invalid Entropy');

    final newChecksum = _calculateEntropyChecksum(entropyBytes);

    if (newChecksum != checksumBits) throw StateError('Invalid Checksum');

    return entropyBytes;
  }

  static String _calculateEntropyChecksum(Uint8List entropy) {
    final binaryEntropySize = entropy.length * 8;
    final checksumSize = binaryEntropySize ~/ 32;
    final hash = SHA256Digest().process(entropy);

    return Uint8List.fromList(hash).toBinaryString().substring(0, checksumSize);
  }
}
