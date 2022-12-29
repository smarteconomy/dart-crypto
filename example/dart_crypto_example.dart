import 'package:dart_crypto/src/model/mnemonic.dart';

void main() {
  var mnemonic = Mnemonic.fromWordCount(wordCount: 15);
  print('Mnemonic: $mnemonic');

  mnemonic = Mnemonic.fromMnemonic(
      "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about");
  print('Mnemonic: $mnemonic');

  var account = mnemonic.createAccount(0);
  print('Account: ${account.toBase58String()}');
}
