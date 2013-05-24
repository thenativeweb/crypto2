'use strict';

var crypto = require('crypto'),
    fs = require('fs');

var ursa = require('ursa');

var createPassword = function (callback) {
  // According to http://de.wikipedia.org/wiki/Base64 the formula for calculating
  // base64's space requirements is: (n + 2 - ((n + 2) % 3)) / 3 * 4. Hence only
  // 24 bytes are required for creating a password with 32 bytes length.
  crypto.randomBytes(24, function (err, buffer) {
    callback(buffer.toString('base64'));
  });
};

var createKeyPair = function (callback) {
  var key = ursa.generatePrivateKey(2048);

  var privateKey = key.toPrivatePem('utf8'),
      publicKey = key.toPublicPem('utf8');

  callback(privateKey, publicKey);
};

var readKey = function (pemFile, fn, callback) {
  fs.readFile(pemFile, function (err, data) {
    callback(fn(data));
  });
};

var readPrivateKey = function (pemFile, callback) {
  readKey(pemFile, ursa.createPrivateKey, callback);
};

var readPublicKey = function (pemFile, callback) {
  readKey(pemFile, ursa.createPublicKey, callback);
};

var aes256cbcEncrypt = function (text, password) {
  var cipher = crypto.createCipher('aes-256-cbc', password);
  cipher.update(text);
  return cipher.final('hex');
};

var aes256cbcDecrypt = function (text, password) {
  var decipher = crypto.createDecipher('aes-256-cbc', password);
  decipher.update(text, 'hex');
  return decipher.final('utf8');
};

var rsaEncrypt = function (text, publicKey) {
  return publicKey.encrypt(text, undefined, 'hex');
};

var rsaDecrypt = function (text, privateKey) {
  return privateKey.decrypt(text, 'hex', 'utf8');
};

var sha256Sign = function (text, publicKey) {
  return publicKey.hashAndSign('sha256', text, undefined, 'hex');
};

var sha256Verify = function (text, publicKey, signature) {
  return publicKey.hashAndVerify('sha256', new Buffer(text), signature, 'hex');
};

var md5 = function (text) {
  var hash = crypto.createHash('md5');
  hash.update(text);
  return hash.digest('hex');
};

var sha1 = function (text) {
  var hash = crypto.createHash('sha1');
  hash.update(text);
  return hash.digest('hex');
};

var sha1hmac = function (text, password) {
  var hmac = crypto.createHmac('sha1', password);
  hmac.update(text);
  return hmac.digest('hex');
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