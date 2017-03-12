'use strict';

const crypto = require('crypto'),
      fs = require('fs'),
      stream = require('stream');

const NodeRSA = require('node-rsa');

const Readable = stream.Readable;

const createPassword = function (callback) {
  // According to http://de.wikipedia.org/wiki/Base64 the formula for calculating
  // base64's space requirements is: (n + 2 - ((n + 2) % 3)) / 3 * 4. Hence only
  // 24 bytes are required for creating a password with 32 bytes length.
  crypto.randomBytes(24, (err, buffer) => {
    if (err) {
      return callback(err);
    }
    callback(null, buffer.toString('base64'));
  });
};

const createKeyPair = function (callback) {
  process.nextTick(() => {
    /* eslint-disable id-length */
    const key = new NodeRSA({ b: 2048, e: 65537 }, { environment: 'node', signingAlgorithm: 'sha256' });
    /* eslint-enable id-length */

    const privateKey = key.exportKey(),
          publicKey = key.exportKey('public');

    callback(null, privateKey, publicKey);
  });
};

const readKey = function (pemFile, keyType, callback) {
  fs.readFile(pemFile, { encoding: 'utf8' }, (err, data) => {
    if (err) {
      return callback(err);
    }

    const key = new NodeRSA(data);

    callback(null, key.exportKey(keyType));
  });
};

const readPrivateKey = function (pemFile, callback) {
  readKey(pemFile, undefined, callback);
};

const readPublicKey = function (pemFile, callback) {
  readKey(pemFile, 'public', callback);
};

const processStream = function (cipher, text, options, callback) {
  let result = '';

  if (cipher instanceof Readable) {
    cipher.setEncoding(options.to);

    cipher.on('readable', () => {
      result += cipher.read() || '';
    });

    cipher.once('end', () => {
      cipher.removeAllListeners();
      callback(null, result);
    });
  } else {
    cipher.once('finish', () => {
      cipher.removeAllListeners();
      callback(null, result);
    });
  }

  cipher.once('error', err => {
    cipher.removeAllListeners();
    callback(err);
  });

  cipher.write(text, options.from);
  cipher.end();
};

const aes256cbcEncrypt = function (text, password, callback) {
  const cipher = crypto.createCipher('aes-256-cbc', password);

  processStream(cipher, text, { from: 'utf8', to: 'hex' }, callback);
};

const aes256cbcDecrypt = function (text, password, callback) {
  const decipher = crypto.createDecipher('aes-256-cbc', password);

  processStream(decipher, text, { from: 'hex', to: 'utf8' }, callback);
};

const rsaEncrypt = function (text, publicKey, callback) {
  process.nextTick(() => {
    const key = new NodeRSA(publicKey);
    const encryptedText = key.encrypt(text, 'base64', 'utf8');

    callback(null, encryptedText);
  });
};

const rsaDecrypt = function (text, privateKey, callback) {
  process.nextTick(() => {
    const key = new NodeRSA(privateKey);
    const decryptedText = key.decrypt(text, 'utf8');

    callback(null, decryptedText);
  });
};

const sha256Sign = function (text, privateKey, callback) {
  const sign = crypto.createSign('RSA-SHA256');

  processStream(sign, text, { from: 'utf8', to: 'utf8' }, err => {
    if (err) {
      return callback(err);
    }

    const signature = sign.sign(privateKey, 'hex');

    callback(null, signature);
  });
};

const sha256Verify = function (text, publicKey, signature, callback) {
  const verify = crypto.createVerify('RSA-SHA256');

  processStream(verify, text, { from: 'utf8', to: 'utf8' }, err => {
    if (err) {
      return callback(err);
    }

    const isSignatureValid = verify.verify(publicKey, signature, 'hex');

    callback(null, isSignatureValid);
  });
};

const md5 = function (text, callback) {
  const hash = crypto.createHash('md5');

  processStream(hash, text, { from: 'utf8', to: 'hex' }, callback);
};

const sha1 = function (text, callback) {
  const hash = crypto.createHash('sha1');

  processStream(hash, text, { from: 'utf8', to: 'hex' }, callback);
};

const sha256 = function (text, callback) {
  const hash = crypto.createHash('sha256');

  processStream(hash, text, { from: 'utf8', to: 'hex' }, callback);
};

const sha1hmac = function (text, password, callback) {
  const hmac = crypto.createHmac('sha1', password);

  processStream(hmac, text, { from: 'utf8', to: 'hex' }, callback);
};

const sha256hmac = function (text, password, callback) {
  const hmac = crypto.createHmac('sha256', password);

  processStream(hmac, text, { from: 'utf8', to: 'hex' }, callback);
};

const crypto2 = {};

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
