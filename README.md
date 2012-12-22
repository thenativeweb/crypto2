# crypto2

crypto2 is a convenience wrapper around Node.js' crypto module.

## Installation

At the moment, installation of this module must be made manually.

## Quick start

The first thing you need to do is to integrate crypto2 into your application. For that add a reference to the `crypto2` module.

```javascript
var crypto2 = require('crypto2');
```

### Encrypting and decrypting

If you want crypto2 to select an encryption algorithm for you, call the `encrypt` and `decrypt` functions without any specific algorithm. This defaults to the AES 256 CBC encryption algorithm.

```javascript
var encrypted = crypto2.encrypt('the native web', 'secret');
// => 6c9ae06e9cd536bf38d0f551f8150065

var decrypted = crypto2.decrypt('6c9ae06e9cd536bf38d0f551f8150065', 'secret');
// => the native web
```

To encrypt and decrypt using the AES 256 CBC encryption algorithm call the `encrypt.aes256cbc` and `decrypt.aes256cbc` functions.

```javascript
var encrypted = crypto2.encrypt.aes256cbc('the native web', 'secret');
// => 6c9ae06e9cd536bf38d0f551f8150065

var decrypted = crypto2.decrypt.aes256cbc('6c9ae06e9cd536bf38d0f551f8150065', 'secret');
// => the native web
```

### Signing and verifying

For signing and verifying you will need a PEM encoded private and public key pair. See [How to create .pem files for https web server](http://stackoverflow.com/questions/12871565/how-to-create-pem-files-for-https-web-server) on how to create them.

To load a key from a `.pem` file call the `readKey` function and specify the name of the key file.

```javascript
crypto2.readKey('key.pem', function (key) {
  // ...
});
```

*NOTE: Please note that you only need to specify a private key file as it contains both the private and the public key.*

If you want crypto2 to select a signing algorithm for you, call the `sign` and `verify` functions without any specific algorithm. This defaults to the SHA256 signing algorithm.

```javascript
var signature = crypto2.sign('the native web', privateKey);
// => [...]

var isSignatureValid = crypto2.verify('the native web', publicKey, signature);
// => true
```

To sign and verify using the SHA256 signing algorithm call the `sign.sha256` and `verify.sha256` functions.

```javascript
var signature = crypto2.sign.sha256('the native web', privateKey);
// => [...]

var isSignatureValid = crypto2.verify.sha256('the native web', publicKey, signature);
// => true
```

### Hashing

If you want crypto2 to select a hash algorithm for you, call the `hash` function without any specific algorithm. This defaults to the SHA1 hash algorithm.

```javascript
var hash = crypto2.hash('the native web');
// => cc762e69089ee2393b061ab26a005319bda94744
```

To calculate the MD5 hash value of a string call the `hash.md5` function.

```javascript
var hash = crypto2.hash.md5('the native web');
// => 4e8ba2e64931c64b63f4dc8d90e1dc7c
```

To calculate the SHA1 hash value of a string call the `hash.sha1` function.

```javascript
var hash = crypto2.hash.sha1('the native web');
// => cc762e69089ee2393b061ab26a005319bda94744
```

## Running the tests

crypto2 has been developed using TDD. To run the tests, go to the folder where you have installed crypto2 to and run `npm test`. You need to have [mocha](https://github.com/visionmedia/mocha) installed.

    $ npm test