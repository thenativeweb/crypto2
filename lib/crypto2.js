'use strict';

var crypto = require('crypto'),
    fs = require('fs');

var ursa = require('ursa');

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
  return decipher.final();
};

var sha256Sign = function (text, privateKey) {
  return privateKey.hashAndSign('sha256', text, 'utf8', 'hex');
};

var sha256Verify = function (text, publicKey, signature) {
  return publicKey.hashAndVerify('sha256', new Buffer(text, 'utf8'), signature, 'hex');
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

crypto2.readPrivateKey = readPrivateKey;
crypto2.readPublicKey = readPublicKey;

crypto2.encrypt = aes256cbcEncrypt;
crypto2.encrypt.aes256cbc = aes256cbcEncrypt;

crypto2.decrypt = aes256cbcDecrypt;
crypto2.decrypt.aes256cbc = aes256cbcDecrypt;

crypto2.sign = sha256Sign;
crypto2.sign.sha256 = sha256Sign;

crypto2.verify = sha256Verify;
crypto2.verify.sha256 = sha256Verify;

crypto2.hash = sha1;
crypto2.hash.md5 = md5;
crypto2.hash.sha1 = sha1;

module.exports = crypto2;