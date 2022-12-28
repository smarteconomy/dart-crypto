import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';
import 'package:bs58check/bs58check.dart' as bs58check;
import 'package:dart_crypto/src/util/extensions.dart';
import 'package:dart_crypto/src/util/crypto_utils.dart';
import 'package:pointycastle/export.dart';

class ExtendedKeyPair {
  final ECPrivateKey privateKey;
  final ECPublicKey publicKey;
  final Uint8List chainCode;
  final int depth;
  final int parentFingerprint;
  final int index;

  ExtendedKeyPair(this.privateKey, this.publicKey, this.chainCode, this.depth,
      this.index, this.parentFingerprint);

  factory ExtendedKeyPair.fromSeed(Uint8List seed,
      {int index = 0,
      String curve = "secp256k1",
      int parentFingerprint = 0,
      int depth = 0}) {
    ECDomainParameters params = ECDomainParameters(curve);
    var hmac = Mac("SHA-512/HMAC");
    hmac.init(KeyParameter(Uint8List.fromList(utf8.encode("Bitcoin seed"))));
    final out = hmac.process(seed);
    var randomPrivateKey = out.sublist(0, 32);
    var chaincode = out.sublist(32, 64);

    var bytePrivateKey = CryptoUtils.readBytes(randomPrivateKey);

    if (bytePrivateKey.compareTo(params.n) >= 0) {
      throw Exception("Invalid Key");
    }

    final privateKey = ECPrivateKey(bytePrivateKey, params);
    final publicKey = privateKey.toPublicKey();
    final extendedKey = ExtendedKeyPair(
        privateKey, publicKey, chaincode, depth, index, parentFingerprint);
    return extendedKey;
  }

  String toBase58String({version = 76066276, neutered = false}) {
    Uint8List buffer = Uint8List(78);
    ByteData bytes = buffer.buffer.asByteData();
    bytes.setUint32(0, version);
    bytes.setUint8(4, depth);
    bytes.setUint32(5, parentFingerprint);
    bytes.setUint32(9, index);
    buffer.setRange(13, 45, chainCode);
    if (!neutered) {
      bytes.setUint8(45, 0);
      buffer.setRange(46, 78, CryptoUtils.writeBigInt(privateKey.d!));
    } else {
      buffer.setRange(45, 78, publicKey.Q!.getEncoded());
    }
    return bs58check.encode(buffer);
  }

  ExtendedKeyPair deriveChildKey(int index, {hardened = true}) {
    final localPrivateKey = this.privateKey.d;
    final localPublicKey = this.publicKey.Q;
    final localParameters = this.publicKey.parameters;

    if (localPrivateKey == null) {
      throw Exception("Invalid private key for hardened derivation");
    }

    if (localPublicKey == null) {
      throw Exception("Invalid public key for derivation");
    }

    if (localParameters == null) {
      throw Exception("Invalid parameters for derivation");
    }

    if (hardened && index < pow(2, 31)) {
      index += pow(2, 31) as int;
    }

    var hmac = Mac("SHA-512/HMAC");
    hmac.init(KeyParameter(this.chainCode));
    Uint8List inputData = Uint8List(37);
    ByteData bytes = inputData.buffer.asByteData();

    if (hardened) {
      inputData[0] = 0;
      inputData.setRange(1, 33, CryptoUtils.writeBigInt(localPrivateKey));
    } else {
      inputData.setRange(0, 33, localPublicKey.getEncoded(true));
    }
    bytes.setUint32(33, index);

    final out = hmac.process(inputData);

    var internalSeed = out.sublist(0, 32);
    var chainCode = out.sublist(32, 64);

    //Sums the private key with the internal seed
    var childKey = (CryptoUtils.readBytes(internalSeed) + localPrivateKey) %
        localParameters.n;

    var parentFingerprint =
        SHA256Digest().process(localPublicKey.getEncoded(true));
    parentFingerprint =
        RIPEMD160Digest().process(parentFingerprint).sublist(0, 4);

    final privateKey = ECPrivateKey(childKey, localParameters);
    final publicKey = privateKey.toPublicKey();

    var newExtendedPrivateKey = ExtendedKeyPair(
        privateKey,
        publicKey,
        chainCode,
        depth + 1,
        index,
        parentFingerprint.buffer.asByteData().getUint32(0));

    return newExtendedPrivateKey;
  }

  ExtendedKeyPair deriveChildKeyFromPath(String fullPath) {
    var path = fullPath.split("/");
    var key = this;
    for (var p in path) {
      if (p == "m") {
        continue;
      }
      var hardened = false;
      if (p.endsWith("'")) {
        hardened = true;
        //Remove ' from the end
        p = p.substring(0, p.length - 1);
      }
      var index = int.parse(p);
      key = key.deriveChildKey(index, hardened: hardened);
    }
    return key;
  }
}
