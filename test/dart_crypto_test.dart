import 'package:dart_crypto/dart_crypto.dart';
import 'package:dart_crypto/src/util/extensions.dart';
import 'package:pointycastle/export.dart';
import 'package:test/expect.dart';
import 'package:test/scaffolding.dart';
import 'assets/bip39_test_vectors.dart';

void main() {
  group("Mnemonic Tests", () {
    test("Bip39 Test Vectors - From Entropy", () {
      for (var element in bip39TestVectorsEnglish) {
        //0 = entropy 1 = mnemonic 2 = seed
        final entropy = element[0];
        final mnemonic = MnemonicHelper.entropyToMnemonic(entropy.hexToBytes());
        expect(mnemonic, element[1]);
        final seed = MnemonicHelper.mnemonicToSeed(mnemonic, 'TREZOR');
        expect(seed.toHexString(), element[2]);
      }
    });

    test("Bip39 Test Vectors - From Menmonic", () {
      for (var element in bip39TestVectorsEnglish) {
        //0 = entropy 1 = mnemonic 2 = seed
        final mnemonic = element[1];
        final entropy = MnemonicHelper.mnemonicToEntropy(mnemonic);
        expect(entropy.toHexString(), element[0]);
        final seed = MnemonicHelper.mnemonicToSeed(mnemonic, 'TREZOR');
        expect(seed.toHexString(), element[2]);
      }
    });

    test("Test Extend Key", () {
      for (var element in bip39TestVectorsEnglish) {
        //0 = entropy 1 = mnemonic 2 = seed
        final mnemonic = element[1];
        final seed = MnemonicHelper.mnemonicToSeed(mnemonic, 'TREZOR');
        final rootKey = ExtendedKey.fromSeed(seed);
        expect(rootKey.toBase58String(), element[3]);
      }
    });

    test("Test Public Key Derivation", () {
      final seed = "000102030405060708090a0b0c0d0e0f".hexToBytes();
      //m/
      final extendedRootPrivateKey =
          ExtendedKey.fromSeed(seed) as ExtendedPrivateKey;
      final encodedPrivateKey = extendedRootPrivateKey.toBase58String();
      expect(encodedPrivateKey,
          "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi");
      final neuteredRootKey = extendedRootPrivateKey.toNeuteredKey();
      expect(
          "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8",
          neuteredRootKey.toBase58String());
      //Public key to public key
      var derivedFromPublicKey = neuteredRootKey.derivePublicChildKey(0);
      var derivedFromPrivateKey = extendedRootPrivateKey
          .derivePrivateChildKey(0, hardened: false)
          .toNeuteredKey();

      expect(derivedFromPrivateKey.toBase58String(),
          derivedFromPublicKey.toBase58String());

      derivedFromPublicKey =
          neuteredRootKey.derivePublicChildKey(0).derivePublicChildKey(0);

      derivedFromPrivateKey = extendedRootPrivateKey
          .derivePrivateChildKey(0, hardened: false)
          .derivePrivateChildKey(0, hardened: false)
          .toNeuteredKey();
    });

    test("Test Child Key Derivation", () {
      final seed = "000102030405060708090a0b0c0d0e0f".hexToBytes();
      //m/
      final extendedRootPrivateKey =
          ExtendedKey.fromSeed(seed) as ExtendedPrivateKey;
      final encodedPrivateKey = extendedRootPrivateKey.toBase58String();
      expect(encodedPrivateKey,
          "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi");
      //Neutered Key xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8

      //m/0'/
      var derivedExtendedPrivateKey =
          extendedRootPrivateKey.derivePrivateChildKey(0);
      var derivedChildKeyEncoded = derivedExtendedPrivateKey.toBase58String();
      expect(derivedChildKeyEncoded,
          "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7");

      var derivedExtendedPublicKey = derivedExtendedPrivateKey.toNeuteredKey();
      var encodedDerivedPublicKey = derivedExtendedPublicKey.toBase58String();
      expect(encodedDerivedPublicKey,
          "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw");

      //m/0/
      derivedExtendedPrivateKey =
          extendedRootPrivateKey.derivePrivateChildKey(0, hardened: false);
      derivedChildKeyEncoded = derivedExtendedPrivateKey.toBase58String();
      expect(derivedChildKeyEncoded,
          "xprv9uHRZZhbkedL37eZEnyrNsQPFZYRAvjy5rt6M1nbEkLSo378x1CQQLo2xxBvREwiK6kqf7GRNvsNEchwibzXaV6i5GcsgyjBeRguXhKsi4R");

      derivedExtendedPublicKey = derivedExtendedPrivateKey.toNeuteredKey();
      encodedDerivedPublicKey = derivedExtendedPublicKey.toBase58String();
      expect(encodedDerivedPublicKey,
          "xpub68Gmy5EVb2BdFbj2LpWrk1M7obNuaPTpT5oh9QCCo5sRfqSHVYWex97WpDZzszdzHzxXDAzPLVSwybe4uPYkSk4G3gnrPqqkV9RyNzAcNJ1");

      // //m/0/0'
      // derivedExtendedPrivateKey =
      //     derivedExtendedPrivateKey.derivePrivateChildKey(0, hardened: true);
      // derivedChildKeyEncoded = derivedExtendedPrivateKey.toBase58String();
      // expect(derivedChildKeyEncoded,
      //     "xprv9ww7sMFVKxty8YzC4nKSgnUKNFM2uSybNoV24kC82UF9JJMgmZF61rNcd5J8M8d5DkxPLT79SgfSYwL6V8PRwNsgYYrRj2BM8eZ2nZEHrsi");
      // encodedDerivedPublicKey = derivedExtendedPrivateKey.toBase58String(
      //     version: int.parse("0488B21E", radix: 16));
      // expect(encodedDerivedPublicKey,
      //     "xpub6AvUGrnPALTGM34fAorT3vR3vHBXJuhSk2Qcs8bjaon8B6gqK6ZLZeh6UMqPaS6a4Q1fByzY74W5L8vB2XedwzhFVaiXW8ggTsuRBRm65ak");

      // //m/0/0'/1'
      // derivedExtendedPrivateKey =
      //     derivedExtendedPrivateKey.derivePrivateChildKey(1, hardened: true);
      // derivedChildKeyEncoded = derivedExtendedPrivateKey.toBase58String();
      // expect(derivedChildKeyEncoded,
      //     "xprv9zBKtvKGUq5YtLP837ucGn49nDbJAUKsEcsqwAy9uaocW1AsucBmU2SM4AGeC6nrU6b3j9vmRRcMfWFQkBf2C3mSLveBPZpxKRH5WZx1dGc");
      // encodedDerivedPublicKey = derivedExtendedPrivateKey.toBase58String(
      //     version: int.parse("0488B21E", radix: 16));
      // expect(encodedDerivedPublicKey,
      //     "xpub6DAgJRrAKCdr6pTb99ScduztLFRnZw3ibqoSjZNmTvLbNoW2T9W21pkpuR3qWHyFfLGL2VTuffBjBabRhRPwGu9KKXbkZ4Fd2tP2QPwZV13");
    });

    test("Test Wif", () {
      final testPrivateKey =
          "45f938530814120090d5e2deddb272d68148c3dabf146a6732d0145b72b9694d"
              .hexToBytes();
      final privateKey = ECPrivateKey(CryptoUtils.readBytes(testPrivateKey),
          ECDomainParameters("secp256k1"));
      final wif = privateKey.toWIF();
      expect(wif, "KyZjJpbKHkz9Mo3f1dEfTFtxBYGSoND48T1jxNDEvkFxpkE2saTs");
    });

    test("Test Derivation with Path", () {
      const mnemonic =
          "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
      final seed = MnemonicHelper.mnemonicToSeed(mnemonic);
      final extendedRootKey = ExtendedKey.fromSeed(seed) as ExtendedPrivateKey;
      //m/0'/0'/0'
      final childKey = extendedRootKey
          .derivePrivateChildKey(0)
          .derivePrivateChildKey(0)
          .derivePrivateChildKey(0);
      final childKeyEncoded = childKey.toBase58String();
      expect(childKeyEncoded,
          "xprv9xirHuqDkUGmnw5eKkdkxZtb5EnFzKtzvHRFvdZCAm2Nnq29U6Cp15NfdnkLNbmsTkqFNgjpbLwdjVemQ7H9cE99sJSQE7NSnKFuNZeQ2xe");

      final pathDerivatedKey =
          extendedRootKey.derivePrivateChildKeyFromPath("m/0'/0'/0'");
      expect(childKeyEncoded, pathDerivatedKey.toBase58String());
    });

    test("Test Derivation with BipPath", () {
      const mnemonic =
          "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
      final seed = MnemonicHelper.mnemonicToSeed(mnemonic);
      final extendedRootKey = ExtendedKey.fromSeed(seed) as ExtendedPrivateKey;
      final childKey = extendedRootKey
          .derivePrivateChildKey(44)
          .derivePrivateChildKey(0)
          .derivePrivateChildKey(0)
          .derivePrivateChildKey(0, hardened: false)
          .derivePrivateChildKey(1);
      final childKeyEncoded = childKey.toBase58String();
      final pathDerivatedKey =
          extendedRootKey.derivePrivateChildKeyFromPath("m/44'/0'/0'/0/1'");
      expect(childKeyEncoded, pathDerivatedKey.toBase58String());
    });
  });
}
