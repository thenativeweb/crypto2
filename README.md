# crypto2

crypto2 is a convenience wrapper around Node.js' crypto module.

## Installation

At the moment, installation of this module must be made manually.

## Quick start

The first thing you need to do is to integrate crypto2 into your application. For that add a reference to the `crypto2` module.

```javascript
var crypto2 = require('crypto2');
```

### Creating passwords

For encrypting and decrypting you will need a password. You can either use an existing one or you can create a new one by calling the `createPassword` function. This function creates passwords with 32 bytes (256 bits) length consisting of lowercase and uppercase letters and digits.

```javascript
crypto2.createPassword(function (err, password) {
  // ...
});
```

### Creating and managing keys

For signing and verifying as well as for encrypting and decrypting using asymmetric encryption algorithms you will need a PEM encoded private and public key pair. You can use the `openssl` command-line tool to create both of them.

    $ openssl genrsa -out key.pem 2048
    $ openssl rsa -in key.pem -pubout > key.pub

Alternatively the key pair may be created programmatically by calling the `createKeyPair` function. This function creates a 2048-bit strong RSA key pair in PEM format.

```javascript
crypto2.createKeyPair(function (err, privateKey, publicKey) {
  // ...
});
```

To load a private key from a `.pem` file call the `readPrivateKey` function and specify the name of the key file.

```javascript
crypto2.readPrivateKey('key.pem', function (err, privateKey) {
  // ...
});
```

To load a public key from a `.pub` file call the `readPublicKey` function and specify the name of the key file.

```javascript
crypto2.readPublicKey('key.pub', function (err, publicKey) {
  // ...
});
```

### Encrypting and decrypting

If you want crypto2 to select an encryption algorithm for you, call the `encrypt` and `decrypt` functions without any specific algorithm. This defaults to the AES 256 CBC encryption algorithm.

```javascript
crypto2.encrypt('the native web', password, function (err, encrypted) {
  // => 6c9ae06e9cd536bf38d0f551f8150065
});

crypto2.decrypt('6c9ae06e9cd536bf38d0f551f8150065', password, function (err, decrypted) {
  // => the native web
});
```

To encrypt and decrypt using the AES 256 CBC encryption algorithm call the `encrypt.aes256cbc` and `decrypt.aes256cbc` functions.

```javascript
crypto2.encrypt.aes256cbc('the native web', password, function (err, encrypted) {
  // => 6c9ae06e9cd536bf38d0f551f8150065
});

crypto2.decrypt.aes256cbc('6c9ae06e9cd536bf38d0f551f8150065', password, function (err, decrypted) {
  // => the native web
});
```

To encrypt and decrypt using the asymmetric RSA encryption algorithm call the `encrypt.rsa` and `decrypt.rsa` functions. Due to technical limitations of the RSA algorithm the text to be encrypted must not be longer than 215 bytes when using keys with 2048 bits.

```javascript
crypto2.encrypt.rsa('the native web', publicKey, function (err, encrypted) {
  // => [...]
});

crypto2.decrypt.rsa(encrypted, privateKey, function (err, decrypted) {
  // => the native web
});
```

### Signing and verifying

If you want crypto2 to select a signing algorithm for you, call the `sign` and `verify` functions without any specific algorithm. This defaults to the SHA256 signing algorithm.

```javascript
crypto2.sign('the native web', privateKey, function (err, signature) {
  // => [...]
});

crypto2.verify('the native web', publicKey, signature, function (err, isSignatureValid) {
  // => true
});
```

To sign and verify using the SHA256 signing algorithm call the `sign.sha256` and `verify.sha256` functions.

```javascript
crypto2.sign.sha256('the native web', privateKey, function (err, signature) {
  // => [...]
});

crypto2.verify.sha256('the native web', publicKey, signature, function (err, isSignatureValid) {
  // => true
});
```

### Hashing

If you want crypto2 to select a hash algorithm for you, call the `hash` function without any specific algorithm. This defaults to the SHA1 hash algorithm.

```javascript
crypto2.hash('the native web', function (err, hash) {
  // => cc762e69089ee2393b061ab26a005319bda94744
});
```

To calculate the MD5 hash value of a string call the `hash.md5` function.

```javascript
crypto2.hash.md5('the native web', function (err, hash) {
  // => 4e8ba2e64931c64b63f4dc8d90e1dc7c
});
```

To calculate the SHA1 hash value of a string call the `hash.sha1` function.

```javascript
crypto2.hash.sha1('the native web', function (err, hash) {
  // => cc762e69089ee2393b061ab26a005319bda94744
});
```

### Message authentication

If you want crypto2 to select a HMAC algorithm for you, call the `hmac` function without any specific algorithm. This defaults to the SHA1 hash algorithm.

```javascript
crypto2.hmac('the native web', 'secret', function (err, hmac) {
  // => c9a6cdb2d350820e76a14f4f9a6392990ce1982a
});
```

To calculate the SHA1-based HMAC value of a string call the `hmac.sha1` function.

```javascript
crypto2.hmac.sha1('the native web', 'secret', function (err, hmac) {
  // => c9a6cdb2d350820e76a14f4f9a6392990ce1982a
});
```

## Running the build

This module can be built using [Grunt](http://gruntjs.com/). Besides running the tests, this also analyses the code. To run Grunt, go to the folder where you have installed tourism and run `grunt`. You need to have [grunt-cli](https://github.com/gruntjs/grunt-cli) installed.

    $ grunt

