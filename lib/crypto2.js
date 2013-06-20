'use strict';

var crypto = require('crypto'),
    fs = require('fs');

var ursa = require('ursa');

var createPassword = function (callback) {
  // According to http://de.wikipedia.org/wiki/Base64 the formula for calculating
  // base64's space requirements is: (n + 2 - ((n + 2) % 3)) / 3 * 4. Hence only
  // 24 bytes are required for creating a password with 32 bytes length.
  crypto.randomBytes(24, function (err, buffer) {
    if (err) {
      return callback(err);
    }
    callback(null, buffer.toString('base64'));
  });
};

var createKeyPair = function (callback) {
  var key = ursa.generatePrivateKey(2048);

  var privateKey = key.toPrivatePem('utf8'),
      publicKey = key.toPublicPem('utf8');

  callback(null, privateKey, publicKey);
};

var readKey = function (pemFile, fn, callback) {
  fs.readFile(pemFile, function (err, data) {
    callback(null, fn(data));
  });
};

var readPrivateKey = function (pemFile, callback) {
  readKey(pemFile, ursa.createPrivateKey, callback);
};

var readPublicKey = function (pemFile, callback) {
  readKey(pemFile, ursa.createPublicKey, callback);
};

var aes256cbcEncrypt = function (text, password, callback) {
  var cipher = crypto.createCipher('aes-256-cbc', password),
      encryptedText = '';

  cipher.setEncoding('hex');
  cipher.write(text, 'utf8');
  cipher.end();

  cipher.on('readable', function () {
    encryptedText += cipher.read();
  });
  cipher.on('end', function () {
    callback(null, encryptedText);
  });
};

var aes256cbcDecrypt = function (text, password, callback) {
  var decipher = crypto.createDecipher('aes-256-cbc', password),
      decryptedText = '';

  decipher.setEncoding('utf8');
  decipher.write(text, 'hex');
  decipher.end();

  decipher.on('readable', function () {
    decryptedText += decipher.read();
  });
  decipher.on('end', function () {
    callback(null, decryptedText);
  });
};

var rsaEncrypt = function (text, publicKey, callback) {
  var encryptedText = publicKey.encrypt(text, undefined, 'hex');
  callback(null, encryptedText);
};

var rsaDecrypt = function (text, privateKey, callback) {
  var decryptedText = privateKey.decrypt(text, 'hex', 'utf8');
  callback(null, decryptedText);
};

var sha256Sign = function (text, publicKey, callback) {
  var signature = publicKey.hashAndSign('sha256', text, undefined, 'hex');
  callback(null, signature);
};

var sha256Verify = function (text, publicKey, signature, callback) {
  var isSignatureValid = publicKey.hashAndVerify('sha256', new Buffer(text), signature, 'hex');
  callback(null, isSignatureValid);
};

var md5 = function (text, callback) {
  var hash = crypto.createHash('md5'),
      hashedText = '';

  hash.setEncoding('hex');
  hash.write(text, 'utf8');
  hash.end();

  hash.on('readable', function () {
    hashedText += hash.read();
  });
  hash.on('end', function () {
    callback(null, hashedText);
  });
};

var sha1 = function (text, callback) {
  var hash = crypto.createHash('sha1'),
      hashedText = '';

  hash.setEncoding('hex');
  hash.write(text, 'utf8');
  hash.end();

  hash.on('readable', function () {
    hashedText += hash.read();
  });
  hash.on('end', function () {
    callback(null, hashedText);
  });
};

var sha1hmac = function (text, password, callback) {
  var hmac = crypto.createHmac('sha1', password),
      hmacedText = '';

  hmac.setEncoding('hex');
  hmac.write(text, 'utf8');
  hmac.end();

  hmac.on('readable', function () {
    hmacedText += hmac.read();
  });
  hmac.on('end', function () {
    callback(null, hmacedText);
  });
};

var crypto2 = {};

crypto2.createPassword = createPassword;

crypto2.createKeyPair = createKeyPair;

crypto2.readPrivateKey = readPrivateKey;
crypto2.readPublicKey = readPublicKey;

crypto2.encrypt = aes256cbcEncrypt;
crypto2.encrypt.aes256cbc = aes256cbcEncrypt;
crypto2.encrypt.rsa = rsaEncrypt;

crypto2.decrypt = aes256cbcDecrypt;
crypto2.decrypt.aes256cbc = aes256cbcDecrypt;
crypto2.decrypt.rsa = rsaDecrypt;

crypto2.sign = sha256Sign;
crypto2.sign.sha256 = sha256Sign;

crypto2.verify = sha256Verify;
crypto2.verify.sha256 = sha256Verify;

crypto2.hash = sha1;
crypto2.hash.md5 = md5;
crypto2.hash.sha1 = sha1;

crypto2.hmac = sha1hmac;
crypto2.hmac.sha1 = sha1hmac;

module.exports = crypto2;