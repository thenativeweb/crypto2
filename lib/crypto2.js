'use strict';

var crypto = require('crypto'),
    fs = require('fs');

var NodeRSA = require('node-rsa');

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
  var key = new NodeRSA({ bits: 2048, exp: 65537 }, { environment: 'node', signingAlgorithm: 'sha256' });

  var privateKey = key.getPrivatePEM(),
      publicKey = key.getPublicPEM('utf8');

  callback(null, privateKey, publicKey);
};

var readKey = function (pemFile, fn, callback) {
  fs.readFile(pemFile, { encoding: 'utf8' }, function (err, data) {
    var key;

    if (err) {
      return callback(err);
    }

    key = new NodeRSA();
    key.loadFromPEM(data);
    callback(null, key[ fn ]());
  });
};

var readPrivateKey = function (pemFile, callback) {
  readKey(pemFile, 'getPrivatePEM', callback);
};

var readPublicKey = function (pemFile, callback) {
  readKey(pemFile, 'getPublicPEM', callback);
};

var processStream = function (stream, text, options, callback) {
  var result = '';

  stream.setEncoding(options.to);
  stream.write(text, options.from);
  stream.end();

  stream.on('readable', function () {
    result += stream.read();
  });

  stream.once('error', function (err) {
    stream.removeAllListeners();
    callback(err);
  });

  stream.once('end', function () {
    stream.removeAllListeners();
    callback(null, result);
  });
};

var aes256cbcEncrypt = function (text, password, callback) {
  var cipher = crypto.createCipher('aes-256-cbc', password);
  processStream(cipher, text, { from: 'utf8', to: 'hex' }, callback);
};

var aes256cbcDecrypt = function (text, password, callback) {
  var decipher = crypto.createDecipher('aes-256-cbc', password);
  processStream(decipher, text, { from: 'hex', to: 'utf8' }, callback);
};

var rsaEncrypt = function (text, publicKey, callback) {
  var key = new NodeRSA(publicKey);
  var encryptedText = key.encrypt(text, 'base64', 'utf8');
  callback(null, encryptedText);
};

var rsaDecrypt = function (text, privateKey, callback) {
  var key = new NodeRSA(privateKey);
  var decryptedText = key.decrypt(text, 'utf8');
  callback(null, decryptedText);
};

var sha256Sign = function (text, publicKey, callback) {
  var key = new NodeRSA(publicKey);
  var signature = key.sign(text, 'hex', 'utf8');
  callback(null, signature);
};

var sha256Verify = function (text, publicKey, signature, callback) {
  var key = new NodeRSA(publicKey);
  var isSignatureValid = key.verify(text, signature, 'utf8', 'hex');
  callback(null, isSignatureValid);
};

var md5 = function (text, callback) {
  var hash = crypto.createHash('md5');
  processStream(hash, text, { from: 'utf8', to: 'hex' }, callback);
};

var sha1 = function (text, callback) {
  var hash = crypto.createHash('sha1');
  processStream(hash, text, { from: 'utf8', to: 'hex' }, callback);
};

var sha256 = function (text, callback) {
  var hash = crypto.createHash('sha256');
  processStream(hash, text, { from: 'utf8', to: 'hex' }, callback);
};

var sha1hmac = function (text, password, callback) {
  var hmac = crypto.createHmac('sha1', password);
  processStream(hmac, text, { from: 'utf8', to: 'hex' }, callback);
};

var sha256hmac = function (text, password, callback) {
  var hmac = crypto.createHmac('sha256', password);
  processStream(hmac, text, { from: 'utf8', to: 'hex' }, callback);
};

var crypto2 = { };

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

crypto2.hash = sha256;
crypto2.hash.md5 = md5;
crypto2.hash.sha1 = sha1;
crypto2.hash.sha256 = sha256;

crypto2.hmac = sha256hmac;
crypto2.hmac.sha1 = sha1hmac;
crypto2.hmac.sha256 = sha256hmac;

module.exports = crypto2;
