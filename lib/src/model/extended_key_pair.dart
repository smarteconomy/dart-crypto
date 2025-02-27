import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';
import 'package:bs58check/bs58check.dart' as bs58check;
import 'package:dart_crypto/dart_crypto.dart';
import 'package:pointycastle/export.dart';

class ExtendedPublicKey extends ExtendedKey {
  ExtendedPublicKey(ECPublicKey publicKey, Uint8List chainCode, int depth,
      int index, int parentFingerprint)
      : super(publicKey, chainCode, depth, index, parentFingerprint);

  @override
  String toBase58String({version = 76067358, neutered = false}) {
    Uint8List buffer = Uint8List(78);
    ByteData bytes = buffer.buffer.asByteData();
    bytes.setUint32(0, version);
    bytes.setUint8(4, depth);
    bytes.setUint32(5, parentFingerprint);
    bytes.setUint32(9, index);
    buffer.setRange(13, 45, chainCode);
    buffer.setRange(45, 78, publicKey.Q!.getEncoded());
    return bs58check.encode(buffer);
  }

  //FromBase58String
  factory ExtendedPublicKey.fromBase58String(String base58String,
      {curve: 'secp256k1'}) {
    var decoded = bs58check.decode(base58String);
    //Unused
    var version = decoded.buffer.asByteData().getUint32(0);
    var depth = decoded.buffer.asByteData().getUint8(4);
    var parentFingerprint = decoded.buffer.asByteData().getUint32(5);
    var index = decoded.buffer.asByteData().getUint32(9);
    var chainCode = decoded.sublist(13, 45);
    var publicKey = decoded.sublist(45, 78);

    var params = ECDomainParameters(curve);
    final Q = params.curve.decodePoint(publicKey);

    return ExtendedPublicKey(
        ECPublicKey(Q, params), chainCode, depth, index, parentFingerprint);
  }

  @override
  ExtendedPublicKey derivePublicChildKey(index) {
    final localPublicKey = publicKey.Q;
    final localParameters = publicKey.parameters;

    if (index >= pow(2, 31) ||
        localPublicKey == null ||
        localParameters == null) {
      throw Exception("Invalid key for derivation");
    }

    var hmac = Mac("SHA-512/HMAC");
    hmac.init(KeyParameter(this.chainCode));
    Uint8List inputData = Uint8List(37);
    ByteData bytes = inputData.buffer.asByteData();
    inputData.setRange(0, 33, localPublicKey.getEncoded(true));
    bytes.setUint32(33, index);

    final out = hmac.process(inputData);

    var internalSeed = out.sublist(0, 32);
    var chainCode = out.sublist(32, 64);

    //Sums the private key with the internal seed
    var derivedPublicKey =
        localParameters.G * CryptoUtils.readBytes(internalSeed);
    derivedPublicKey = derivedPublicKey! + localPublicKey;

    var hexIdentifier = identifier();
    var parentFingerprint = hexIdentifier.sublist(0, 4);

    var newExtendedPrivateKey = ExtendedPublicKey(
        ECPublicKey(derivedPublicKey, localParameters),
        chainCode,
        depth + 1,
        index,
        parentFingerprint.buffer.asByteData().getUint32(0));

    return newExtendedPrivateKey;
  }
}

class ExtendedPrivateKey extends ExtendedKey {
  final ECPrivateKey privateKey;

  ExtendedPrivateKey(this.privateKey, ECPublicKey publicKey,
      Uint8List chainCode, int depth, int index, int parentFingerprint)
      : super(publicKey, chainCode, depth, index, parentFingerprint);

  @override
  String toBase58String({version = 76066276}) {
    Uint8List buffer = Uint8List(78);
    ByteData bytes = buffer.buffer.asByteData();
    bytes.setUint32(0, version);
    bytes.setUint8(4, depth);
    bytes.setUint32(5, parentFingerprint);
    bytes.setUint32(9, index);
    buffer.setRange(13, 45, chainCode);
    bytes.setUint8(45, 0);
    buffer.setRange(46, 78, CryptoUtils.writeBigInt(privateKey.d!));
    return bs58check.encode(buffer);
  }

  factory ExtendedPrivateKey.fromBase58String(String base58String,
      {curve: 'secp256k1'}) {
    var decoded = bs58check.decode(base58String);
    //Unused
    var version = decoded.buffer.asByteData().getUint32(0);
    var depth = decoded.buffer.asByteData().getUint8(4);
    var parentFingerprint = decoded.buffer.asByteData().getUint32(5);
    var index = decoded.buffer.asByteData().getUint32(9);
    var chainCode = decoded.sublist(13, 45);
    var privateKey = decoded.sublist(46, 78);
    var params = ECDomainParameters(curve);
    final d = CryptoUtils.readBytes(privateKey);

    return ExtendedPrivateKey(
        ECPrivateKey(d, params),
        ECPublicKey(params.G * d, params),
        chainCode,
        depth,
        index,
        parentFingerprint);
  }

  ExtendedPublicKey toNeuteredKey() {
    return ExtendedPublicKey(
        publicKey, chainCode, depth, index, parentFingerprint);
  }

  /*
  * Private parent key → public child key
  */
  @override
  ExtendedPublicKey derivePublicChildKey(index) {
    final derivedPublicKey = derivePrivateChildKey(index).toNeuteredKey();
    return derivedPublicKey;
  }

  /*
  * Private parent key → private child key
  */
  ExtendedPrivateKey derivePrivateChildKey(int index, {hardened = true}) {
    final localPrivateKey = this.privateKey.d;
    final localPublicKey = this.publicKey.Q;
    final localParameters = this.publicKey.parameters;

    if (localPrivateKey == null ||
        localPublicKey == null ||
        localParameters == null) {
      throw Exception("Invalid key for derivation");
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

    var hexIdentifier = identifier();
    var parentFingerprint = hexIdentifier.sublist(0, 4);

    final privateKey = ECPrivateKey(childKey, localParameters);
    final publicKey = privateKey.toPublicKey();

    var newExtendedPrivateKey = ExtendedPrivateKey(
        privateKey,
        publicKey,
        chainCode,
        depth + 1,
        index,
        parentFingerprint.buffer.asByteData().getUint32(0));

    return newExtendedPrivateKey;
  }
}

abstract class ExtendedKey {
  final ECPublicKey publicKey;
  final Uint8List chainCode;
  final int depth;
  final int parentFingerprint;
  final int index;

  ExtendedKey(this.publicKey, this.chainCode, this.depth, this.index,
      this.parentFingerprint) {
    if (CryptoUtils.readBytes(chainCode).compareTo(BigInt.from(0)) == 0) {
      throw Exception("Invalid Chain Code");
    }

    if (depth == 0 && parentFingerprint != 0) {
      throw Exception("Invalid Parent Fingerprint");
    }
  }

  factory ExtendedKey.fromSeed(Uint8List seed,
      {int index = 0,
      String curve = "secp256k1",
      int parentFingerprint = 0,
      int depth = 0}) {
    final params = ECDomainParameters(curve);
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
    final extendedKey = ExtendedPrivateKey(
        privateKey, publicKey, chaincode, depth, index, parentFingerprint);
    return extendedKey;
  }

  String toBase58String({version = 76066276});

  ExtendedPublicKey derivePublicChildKey(index);

  Uint8List identifier() {
    var hash = SHA256Digest().process(publicKey.Q!.getEncoded());
    hash = RIPEMD160Digest().process(hash);
    return hash;
  }

  ExtendedKey deriveChildKeyFromPath(String fullPath) {
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
      if (key is ExtendedPrivateKey) {
        key = key.derivePrivateChildKey(index, hardened: hardened);
      } else {
        if (hardened) {
          throw Exception("Can't derive hardened key from public key");
        }
        key = key.derivePublicChildKey(index);
      }
    }
    return key;
  }
}
