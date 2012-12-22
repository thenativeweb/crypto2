var crypto = require('crypto');

var aes256cbcDecrypt = function (text, password) {
  var decipher = crypto.createDecipher('aes-256-cbc', password);
  decipher.update(text, 'hex');
  return decipher.final();
};

var aes256cbcEncrypt = function (text, password) {
  var cipher = crypto.createCipher('aes-256-cbc', password);
  cipher.update(text);
  return cipher.final('hex');
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

crypto2.decrypt = aes256cbcDecrypt;
crypto2.decrypt.aes256cbc = aes256cbcDecrypt;

crypto2.encrypt = aes256cbcEncrypt;
crypto2.encrypt.aes256cbc = aes256cbcEncrypt;

crypto2.hash = sha1;
crypto2.hash.md5 = md5;
crypto2.hash.sha1 = sha1;

module.exports = crypto2;