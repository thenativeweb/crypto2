'use strict';

var crypto = require('crypto'),
    fs = require('fs');

var readKey = function (pemFile, callback) {
  fs.readFile(pemFile, function (err, data) {
    callback(data.toString('ascii'));
  });
};

var aes256cbcEncrypt = function (text, password) {
  var cipher = crypto.createCipher('aes-256-cbc', password);
  cipher.update(text);
  return cipher.final('hex');
};

var aes256cbcDecrypt = function (text, password) {
  var decipher = crypto.createDecipher('aes-256-cbc', password);
  decipher.update(text, 'hex');
  return decipher.final();
};

var rsasha256Sign = function (text, privateKey) {
  var signer = crypto.createSign('RSA-SHA256');
  signer.update(text);
  return signer.sign(privateKey, 'hex');
};

var rsasha256Verify = function (text, publicKey, signature) {
  var verifier = crypto.createVerify('RSA-SHA256');
  verifier.update(text);
  return verifier.verify(publicKey, signature, 'hex');
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

var crypto2 = {};

crypto2.readKey = readKey;

crypto2.encrypt = aes256cbcEncrypt;
crypto2.encrypt.aes256cbc = aes256cbcEncrypt;

crypto2.decrypt = aes256cbcDecrypt;
crypto2.decrypt.aes256cbc = aes256cbcDecrypt;

crypto2.sign = rsasha256Sign;
crypto2.sign.rsasha256 = rsasha256Sign;

crypto2.verify = rsasha256Verify;
crypto2.verify.rsasha256 = rsasha256Verify;

crypto2.hash = sha1;
crypto2.hash.md5 = md5;
crypto2.hash.sha1 = sha1;

module.exports = crypto2;