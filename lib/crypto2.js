var crypto = require('crypto');

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
crypto2.hash = sha1;
crypto2.hash.md5 = md5;
crypto2.hash.sha1 = sha1;

module.exports = crypto2;