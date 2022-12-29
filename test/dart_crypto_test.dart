import 'dart:math';
import 'dart:typed_data';

import 'package:convert/convert.dart';
import 'package:dart_crypto/dart_crypto.dart';
import 'package:dart_crypto/src/util/extensions.dart';
import 'package:pointycastle/export.dart';
import 'package:test/expect.dart';
import 'package:test/scaffolding.dart';
import 'assets/bip39_test_vectors.dart';
import 'assets/bip32_test_vectors.dart';

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

    test("Bip32 Test Vector1", () {
      final seed = testVector1['seed'] as String;
      final rootKey =
          ExtendedKey.fromSeed(Uint8List.fromList(hex.decode(seed)));
      final testKeys = testVector1['elements'] as List;
      for (var element in testKeys) {
        final path = element['name'];
        final xpub = element['ext_pub'];
        final xpriv = element['ext_prv'];

        final derivedKey =
            rootKey.derivePrivateChildKeyFromPath(path) as ExtendedPrivateKey;
        expect(derivedKey.toBase58String(), xpriv);
        expect(derivedKey.toNeuteredKey().toBase58String(), xpub);
      }
    });

    test("Bip32 Test Vector2", () {
      final seed = testVector2['seed'] as String;
      final rootKey =
          ExtendedKey.fromSeed(Uint8List.fromList(hex.decode(seed)));
      final testKeys = testVector2['elements'] as List;
      for (var element in testKeys) {
        final path = element['name'];
        final xpub = element['ext_pub'];
        final xpriv = element['ext_prv'];

        final derivedKey =
            rootKey.derivePrivateChildKeyFromPath(path) as ExtendedPrivateKey;
        expect(derivedKey.toBase58String(), xpriv);
        expect(derivedKey.toNeuteredKey().toBase58String(), xpub);
      }
    });

    test("Bip32 Test Vector3", () {
      final seed = testVector3['seed'] as String;
      final rootKey =
          ExtendedKey.fromSeed(Uint8List.fromList(hex.decode(seed)));
      final testKeys = testVector3['elements'] as List;
      for (var element in testKeys) {
        final path = element['name'];
        final xpub = element['ext_pub'];
        final xpriv = element['ext_prv'];

        final derivedKey =
            rootKey.derivePrivateChildKeyFromPath(path) as ExtendedPrivateKey;
        expect(derivedKey.toBase58String(), xpriv);
        expect(derivedKey.toNeuteredKey().toBase58String(), xpub);
      }
    });

    test("Bip32 Test Vector4", () {
      final seed = testVector4['seed'] as String;
      final rootKey =
          ExtendedKey.fromSeed(Uint8List.fromList(hex.decode(seed)));
      final testKeys = testVector4['elements'] as List;
      for (var element in testKeys) {
        final path = element['name'];
        final xpub = element['ext_pub'];
        final xpriv = element['ext_prv'];

        final derivedKey =
            rootKey.derivePrivateChildKeyFromPath(path) as ExtendedPrivateKey;
        expect(derivedKey.toBase58String(), xpriv);
        expect(derivedKey.toNeuteredKey().toBase58String(), xpub);
      }
    });

    test("Bip32 Test Vector5", () {
      final vector1 =
          "xpub661MyMwAqRbcEYS8w7XLSVeEsBXy79zSzH1J8vCdxAZningWLdN3zgtU6LBpB85b3D2yc8sfvZU521AAwdZafEz7mnzBBsz4wKY5fTtTQBm";
      expect(() => ExtendedPublicKey.fromBase58String(vector1),
          throwsArgumentError);

      final vector2 =
          "xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzFGTQQD3dC4H2D5GBj7vWvSQaaBv5cxi9gafk7NF3pnBju6dwKvH";
      expect(
          () => ExtendedPrivateKey.fromBase58String(vector2), throwsException);

      final vector3 =
          "xpub661MyMwAqRbcEYS8w7XLSVeEsBXy79zSzH1J8vCdxAZningWLdN3zgtU6Txnt3siSujt9RCVYsx4qHZGc62TG4McvMGcAUjeuwZdduYEvFn";
      expect(() => ExtendedPublicKey.fromBase58String(vector3),
          throwsArgumentError);

      final vector4 =
          "xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzFGpWnsj83BHtEy5Zt8CcDr1UiRXuWCmTQLxEK9vbz5gPstX92JQ";
      expect(
          () => ExtendedPrivateKey.fromBase58String(vector4), throwsException);

      final vector5 =
          "xpub661MyMwAqRbcEYS8w7XLSVeEsBXy79zSzH1J8vCdxAZningWLdN3zgtU6N8ZMMXctdiCjxTNq964yKkwrkBJJwpzZS4HS2fxvyYUA4q2Xe4";
      expect(() => ExtendedPublicKey.fromBase58String(vector5),
          throwsArgumentError);

      final vector6 =
          "xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzFAzHGBP2UuGCqWLTAPLcMtD9y5gkZ6Eq3Rjuahrv17fEQ3Qen6J";
      expect(
          () => ExtendedPrivateKey.fromBase58String(vector6), throwsException);

      final vector7 =
          "xprv9s2SPatNQ9Vc6GTbVMFPFo7jsaZySyzk7L8n2uqKXJen3KUmvQNTuLh3fhZMBoG3G4ZW1N2kZuHEPY53qmbZzCHshoQnNf4GvELZfqTUrcv";
      expect(
          () => ExtendedPrivateKey.fromBase58String(vector7), throwsException);

      final vector8 =
          "xpub661no6RGEX3uJkY4bNnPcw4URcQTrSibUZ4NqJEw5eBkv7ovTwgiT91XX27VbEXGENhYRCf7hyEbWrR3FewATdCEebj6znwMfQkhRYHRLpJ";

      expect(
          () => ExtendedPublicKey.fromBase58String(vector8), throwsException);

      final vector9 =
          "xprv9s21ZrQH4r4TsiLvyLXqM9P7k1K3EYhA1kkD6xuquB5i39AU8KF42acDyL3qsDbU9NmZn6MsGSUYZEsuoePmjzsB3eFKSUEh3Gu1N3cqVUN";

      expect(
          () => ExtendedPrivateKey.fromBase58String(vector9), throwsException);

      final vector10 =
          "xpub661MyMwAuDcm6CRQ5N4qiHKrJ39Xe1R1NyfouMKTTWcguwVcfrZJaNvhpebzGerh7gucBvzEQWRugZDuDXjNDRmXzSZe4c7mnTK97pTvGS8";

      expect(
          () => ExtendedPublicKey.fromBase58String(vector10), throwsException);

      final vector11 =
          "DMwo58pR1QLEFihHiXPVykYB6fJmsTeHvyTp7hRThAtCX8CvYzgPcn8XnmdfHGMQzT7ayAmfo4z3gY5KfbrZWZ6St24UVf2Qgo6oujFktLHdHY4";
      expect(() => ExtendedPublicKey.fromBase58String(vector11),
          throwsArgumentError);
      expect(
          () => ExtendedPrivateKey.fromBase58String(vector11), throwsException);
      final vector12 =
          "DMwo58pR1QLEFihHiXPVykYB6fJmsTeHvyTp7hRThAtCX8CvYzgPcn8XnmdfHPmHJiEDXkTiJTVV9rHEBUem2mwVbbNfvT2MTcAqj3nesx8uBf9";

      expect(
          () => ExtendedPublicKey.fromBase58String(vector12), throwsException);
      expect(
          () => ExtendedPrivateKey.fromBase58String(vector12), throwsException);

      final vector13 =
          "xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzF93Y5wvzdUayhgkkFoicQZcP3y52uPPxFnfoLZB21Teqt1VvEHx";

      expect(
          () => ExtendedPrivateKey.fromBase58String(vector13), throwsException);

      final vector14 =
          "xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzFAzHGBP2UuGCqWLTAPLcMtD5SDKr24z3aiUvKr9bJpdrcLg1y3G";

      expect(
          () => ExtendedPrivateKey.fromBase58String(vector14), throwsException);
    });

    test("Base58 Public Key Decode Tests", () {
      final publicKey =
          "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8";

      final decodedPublicKey = ExtendedPublicKey.fromBase58String(publicKey);
      expect(decodedPublicKey.toBase58String(), publicKey);

      final privateKey =
          "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi";

      final decodedPrivateKey = ExtendedPrivateKey.fromBase58String(privateKey);
      expect(decodedPrivateKey.toBase58String(), privateKey);
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
