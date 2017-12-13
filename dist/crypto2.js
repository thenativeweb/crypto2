'use strict';

var crypto = require('crypto'),
    fs = require('fs'),
    stream = require('stream');

var NodeRSA = require('node-rsa');

var Readable = stream.Readable;

var createPassword = function createPassword(callback) {
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

var createKeyPair = function createKeyPair(callback) {
  process.nextTick(function () {
    /* eslint-disable id-length */
    var key = new NodeRSA({ b: 2048, e: 65537 }, { environment: 'node', signingAlgorithm: 'sha256' });
    /* eslint-enable id-length */

    var privateKey = key.exportKey(),
        publicKey = key.exportKey('public');

    callback(null, privateKey, publicKey);
  });
};

var readKey = function readKey(pemFile, keyType, callback) {
  fs.readFile(pemFile, { encoding: 'utf8' }, function (err, data) {
    if (err) {
      return callback(err);
    }

    var key = new NodeRSA(data);

    callback(null, key.exportKey(keyType));
  });
};

var readPrivateKey = function readPrivateKey(pemFile, callback) {
  readKey(pemFile, undefined, callback);
};

var readPublicKey = function readPublicKey(pemFile, callback) {
  readKey(pemFile, 'public', callback);
};

var processStream = function processStream(cipher, text, options, callback) {
  var result = '';

  if (cipher instanceof Readable) {
    cipher.setEncoding(options.to);

    cipher.on('readable', function () {
      result += cipher.read() || '';
    });

    cipher.once('end', function () {
      cipher.removeAllListeners();
      callback(null, result);
    });
  } else {
    cipher.once('finish', function () {
      cipher.removeAllListeners();
      callback(null, result);
    });
  }

  cipher.once('error', function (err) {
    cipher.removeAllListeners();
    callback(err);
  });

  try {
    cipher.write(text, options.from);
    cipher.end();
  } catch (ex) {
    return callback(ex);
  }
};

var aes256cbcEncrypt = function aes256cbcEncrypt(text, password, callback) {
  var cipher = crypto.createCipher('aes-256-cbc', password);

  processStream(cipher, text, { from: 'utf8', to: 'hex' }, callback);
};

var aes256cbcDecrypt = function aes256cbcDecrypt(text, password, callback) {
  var decipher = crypto.createDecipher('aes-256-cbc', password);

  processStream(decipher, text, { from: 'hex', to: 'utf8' }, callback);
};

var rsaEncrypt = function rsaEncrypt(text, publicKey, callback) {
  process.nextTick(function () {
    var key = new NodeRSA(publicKey);
    var encryptedText = key.encrypt(text, 'base64', 'utf8');

    callback(null, encryptedText);
  });
};

var rsaDecrypt = function rsaDecrypt(text, privateKey, callback) {
  process.nextTick(function () {
    var key = new NodeRSA(privateKey);

    var decryptedText = void 0;

    try {
      decryptedText = key.decrypt(text, 'utf8');
    } catch (ex) {
      return callback(ex);
    }

    callback(null, decryptedText);
  });
};

var sha256Sign = function sha256Sign(text, privateKey, callback) {
  var sign = crypto.createSign('RSA-SHA256');

  processStream(sign, text, { from: 'utf8', to: 'utf8' }, function (err) {
    if (err) {
      return callback(err);
    }

    var signature = sign.sign(privateKey, 'hex');

    callback(null, signature);
  });
};

var sha256Verify = function sha256Verify(text, publicKey, signature, callback) {
  var verify = crypto.createVerify('RSA-SHA256');

  processStream(verify, text, { from: 'utf8', to: 'utf8' }, function (err) {
    if (err) {
      return callback(err);
    }

    var isSignatureValid = verify.verify(publicKey, signature, 'hex');

    callback(null, isSignatureValid);
  });
};

var md5 = function md5(text, callback) {
  var hash = crypto.createHash('md5');

  processStream(hash, text, { from: 'utf8', to: 'hex' }, callback);
};

var sha1 = function sha1(text, callback) {
  var hash = crypto.createHash('sha1');

  processStream(hash, text, { from: 'utf8', to: 'hex' }, callback);
};

var sha256 = function sha256(text, callback) {
  var hash = crypto.createHash('sha256');

  processStream(hash, text, { from: 'utf8', to: 'hex' }, callback);
};

var sha1hmac = function sha1hmac(text, password, callback) {
  var hmac = crypto.createHmac('sha1', password);

  processStream(hmac, text, { from: 'utf8', to: 'hex' }, callback);
};

var sha256hmac = function sha256hmac(text, password, callback) {
  var hmac = crypto.createHmac('sha256', password);

  processStream(hmac, text, { from: 'utf8', to: 'hex' }, callback);
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

crypto2.hash = sha256;
crypto2.hash.md5 = md5;
crypto2.hash.sha1 = sha1;
crypto2.hash.sha256 = sha256;

crypto2.hmac = sha256hmac;
crypto2.hmac.sha1 = sha1hmac;
crypto2.hmac.sha256 = sha256hmac;

module.exports = crypto2;