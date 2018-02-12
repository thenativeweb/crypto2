'use strict';

const crypto = require('crypto'),
      fs = require('fs'),
      { Readable } = require('stream');

const NodeRSA = require('node-rsa'),
      promisify = require('util.promisify');

const randomBytes = promisify(crypto.randomBytes),
      readFile = promisify(fs.readFile);

const createPassword = async function () {
  // According to http://de.wikipedia.org/wiki/Base64 the formula for calculating
  // base64's space requirements is: (n + 2 - ((n + 2) % 3)) / 3 * 4. Hence only
  // 24 bytes are required for creating a password with 32 bytes length.
  const buffer = await randomBytes(24);
  const password = buffer.toString('base64');

  return password;
};

const createKeyPair = async function () {
  /* eslint-disable id-length */
  const key = new NodeRSA({ b: 2048, e: 65537 }, { environment: 'node', signingAlgorithm: 'sha256' });
  /* eslint-enable id-length */

  const privateKey = key.exportKey(),
        publicKey = key.exportKey('public');

  return { privateKey, publicKey };
};

const readKey = async function (pemFile, keyType) {
  const data = await readFile(pemFile, { encoding: 'utf8' });
  const key = new NodeRSA(data);

  const exportedKey = key.exportKey(keyType);

  return exportedKey;
};

const readPrivateKey = async function (pemFile) {
  const privateKey = await readKey(pemFile);

  return privateKey;
};

const readPublicKey = async function (pemFile) {
  const publicKey = await readKey(pemFile, 'public');

  return publicKey;
};

const processStream = function (cipher, text, options) {
  return new Promise((resolve, reject) => {
    let result = '';

    if (cipher instanceof Readable) {
      cipher.setEncoding(options.to);

      cipher.on('readable', () => {
        result += cipher.read() || '';
      });

      cipher.once('end', () => {
        cipher.removeAllListeners();
        resolve(result);
      });
    } else {
      cipher.once('finish', () => {
        cipher.removeAllListeners();
        resolve(result);
      });
    }

    cipher.once('error', err => {
      cipher.removeAllListeners();
      reject(err);
    });

    try {
      cipher.write(text, options.from);
      cipher.end();
    } catch (ex) {
      reject(ex);
    }
  });
};

const aes256cbcEncrypt = async function (text, password) {
  const cipher = crypto.createCipher('aes-256-cbc', password);
  const encrypted = await processStream(cipher, text, { from: 'utf8', to: 'hex' });

  return encrypted;
};

const aes256cbcDecrypt = async function (text, password) {
  const decipher = crypto.createDecipher('aes-256-cbc', password);
  const decrypted = await processStream(decipher, text, { from: 'hex', to: 'utf8' });

  return decrypted;
};

const rsaEncrypt = async function (text, publicKey) {
  const key = new NodeRSA(publicKey);
  const encrypted = key.encrypt(text, 'base64', 'utf8');

  return encrypted;
};

const rsaDecrypt = async function (text, privateKey) {
  const key = new NodeRSA(privateKey);
  const decrypted = key.decrypt(text, 'utf8');

  return decrypted;
};

const sha256Sign = async function (text, privateKey) {
  const sign = crypto.createSign('RSA-SHA256');

  await processStream(sign, text, { from: 'utf8', to: 'utf8' });

  const signature = sign.sign(privateKey, 'hex');

  return signature;
};

const sha256Verify = async function (text, publicKey, signature) {
  const verify = crypto.createVerify('RSA-SHA256');

  await processStream(verify, text, { from: 'utf8', to: 'utf8' });

  const isSignatureValid = verify.verify(publicKey, signature, 'hex');

  return isSignatureValid;
};

const md5 = async function (text) {
  const hash = crypto.createHash('md5');
  const hashValue = await processStream(hash, text, { from: 'utf8', to: 'hex' });

  return hashValue;
};

const sha1 = async function (text) {
  const hash = crypto.createHash('sha1');
  const hashValue = await processStream(hash, text, { from: 'utf8', to: 'hex' });

  return hashValue;
};

const sha256 = async function (text) {
  const hash = crypto.createHash('sha256');
  const hashValue = await processStream(hash, text, { from: 'utf8', to: 'hex' });

  return hashValue;
};

const sha1hmac = async function (text, password) {
  const hmac = crypto.createHmac('sha1', password);
  const hashValue = await processStream(hmac, text, { from: 'utf8', to: 'hex' });

  return hashValue;
};

const sha256hmac = async function (text, password) {
  const hmac = crypto.createHmac('sha256', password);
  const hashValue = await processStream(hmac, text, { from: 'utf8', to: 'hex' });

  return hashValue;
};

const crypto2 = {
  createPassword,
  createKeyPair,
  readPrivateKey,
  readPublicKey,

  encrypt: aes256cbcEncrypt,
  decrypt: aes256cbcDecrypt,

  sign: sha256Sign,
  verify: sha256Verify,

  hash: sha256,
  hmac: sha256hmac
};

crypto2.encrypt.aes256cbc = aes256cbcEncrypt;
crypto2.encrypt.rsa = rsaEncrypt;
crypto2.decrypt.aes256cbc = aes256cbcDecrypt;
crypto2.decrypt.rsa = rsaDecrypt;

crypto2.sign.sha256 = sha256Sign;
crypto2.verify.sha256 = sha256Verify;

crypto2.hash.md5 = md5;
crypto2.hash.sha1 = sha1;
crypto2.hash.sha256 = sha256;
crypto2.hmac.sha1 = sha1hmac;
crypto2.hmac.sha256 = sha256hmac;

module.exports = crypto2;
