import 'package:dart_crypto/src/model/mnemonic.dart';

void main() {
  var mnemonic = MnemonicWallet.fromWordCount(wordCount: 15);
  print('Mnemonic: $mnemonic');

  mnemonic = MnemonicWallet.fromMnemonic(
      "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about");
  print('Mnemonic: $mnemonic');

  var account = mnemonic.createAccountKey(0);
  print('Account: ${account.toBase58String()}');
}
