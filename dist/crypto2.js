'use strict';

function _asyncToGenerator(fn) { return function () { var gen = fn.apply(this, arguments); return new Promise(function (resolve, reject) { function step(key, arg) { try { var info = gen[key](arg); var value = info.value; } catch (error) { reject(error); return; } if (info.done) { resolve(value); } else { return Promise.resolve(value).then(function (value) { step("next", value); }, function (err) { step("throw", err); }); } } return step("next"); }); }; }

var crypto = require('crypto'),
    fs = require('fs'),
    _require = require('stream'),
    Readable = _require.Readable;


var NodeRSA = require('node-rsa'),
    promisify = require('util.promisify');

var randomBytes = promisify(crypto.randomBytes),
    readFile = promisify(fs.readFile);

var createPassword = function () {
  var _ref = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee() {
    var buffer, password;
    return regeneratorRuntime.wrap(function _callee$(_context) {
      while (1) {
        switch (_context.prev = _context.next) {
          case 0:
            _context.next = 2;
            return randomBytes(24);

          case 2:
            buffer = _context.sent;
            password = buffer.toString('base64');
            return _context.abrupt('return', password);

          case 5:
          case 'end':
            return _context.stop();
        }
      }
    }, _callee, this);
  }));

  return function createPassword() {
    return _ref.apply(this, arguments);
  };
}();

var createKeyPair = function () {
  var _ref2 = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee2() {
    var key, privateKey, publicKey;
    return regeneratorRuntime.wrap(function _callee2$(_context2) {
      while (1) {
        switch (_context2.prev = _context2.next) {
          case 0:
            /* eslint-disable id-length */
            key = new NodeRSA({ b: 2048, e: 65537 }, { environment: 'node', signingAlgorithm: 'sha256' });
            /* eslint-enable id-length */

            privateKey = key.exportKey(), publicKey = key.exportKey('public');
            return _context2.abrupt('return', { privateKey: privateKey, publicKey: publicKey });

          case 3:
          case 'end':
            return _context2.stop();
        }
      }
    }, _callee2, this);
  }));

  return function createKeyPair() {
    return _ref2.apply(this, arguments);
  };
}();

var readKey = function () {
  var _ref3 = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee3(pemFile, keyType) {
    var data, key, exportedKey;
    return regeneratorRuntime.wrap(function _callee3$(_context3) {
      while (1) {
        switch (_context3.prev = _context3.next) {
          case 0:
            _context3.next = 2;
            return readFile(pemFile, { encoding: 'utf8' });

          case 2:
            data = _context3.sent;
            key = new NodeRSA(data);
            exportedKey = key.exportKey(keyType);
            return _context3.abrupt('return', exportedKey);

          case 6:
          case 'end':
            return _context3.stop();
        }
      }
    }, _callee3, this);
  }));

  return function readKey(_x, _x2) {
    return _ref3.apply(this, arguments);
  };
}();

var readPrivateKey = function () {
  var _ref4 = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee4(pemFile) {
    var privateKey;
    return regeneratorRuntime.wrap(function _callee4$(_context4) {
      while (1) {
        switch (_context4.prev = _context4.next) {
          case 0:
            _context4.next = 2;
            return readKey(pemFile);

          case 2:
            privateKey = _context4.sent;
            return _context4.abrupt('return', privateKey);

          case 4:
          case 'end':
            return _context4.stop();
        }
      }
    }, _callee4, this);
  }));

  return function readPrivateKey(_x3) {
    return _ref4.apply(this, arguments);
  };
}();

var readPublicKey = function () {
  var _ref5 = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee5(pemFile) {
    var publicKey;
    return regeneratorRuntime.wrap(function _callee5$(_context5) {
      while (1) {
        switch (_context5.prev = _context5.next) {
          case 0:
            _context5.next = 2;
            return readKey(pemFile, 'public');

          case 2:
            publicKey = _context5.sent;
            return _context5.abrupt('return', publicKey);

          case 4:
          case 'end':
            return _context5.stop();
        }
      }
    }, _callee5, this);
  }));

  return function readPublicKey(_x4) {
    return _ref5.apply(this, arguments);
  };
}();

var processStream = function processStream(cipher, text, options) {
  return new Promise(function (resolve, reject) {
    var result = '';

    if (cipher instanceof Readable) {
      cipher.setEncoding(options.to);

      cipher.on('readable', function () {
        result += cipher.read() || '';
      });

      cipher.once('end', function () {
        cipher.removeAllListeners();
        resolve(result);
      });
    } else {
      cipher.once('finish', function () {
        cipher.removeAllListeners();
        resolve(result);
      });
    }

    cipher.once('error', function (err) {
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

var aes256cbcEncrypt = function () {
  var _ref6 = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee6(text, password) {
    var cipher, encrypted;
    return regeneratorRuntime.wrap(function _callee6$(_context6) {
      while (1) {
        switch (_context6.prev = _context6.next) {
          case 0:
            cipher = crypto.createCipher('aes-256-cbc', password);
            _context6.next = 3;
            return processStream(cipher, text, { from: 'utf8', to: 'hex' });

          case 3:
            encrypted = _context6.sent;
            return _context6.abrupt('return', encrypted);

          case 5:
          case 'end':
            return _context6.stop();
        }
      }
    }, _callee6, this);
  }));

  return function aes256cbcEncrypt(_x5, _x6) {
    return _ref6.apply(this, arguments);
  };
}();

var aes256cbcDecrypt = function () {
  var _ref7 = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee7(text, password) {
    var decipher, decrypted;
    return regeneratorRuntime.wrap(function _callee7$(_context7) {
      while (1) {
        switch (_context7.prev = _context7.next) {
          case 0:
            decipher = crypto.createDecipher('aes-256-cbc', password);
            _context7.next = 3;
            return processStream(decipher, text, { from: 'hex', to: 'utf8' });

          case 3:
            decrypted = _context7.sent;
            return _context7.abrupt('return', decrypted);

          case 5:
          case 'end':
            return _context7.stop();
        }
      }
    }, _callee7, this);
  }));

  return function aes256cbcDecrypt(_x7, _x8) {
    return _ref7.apply(this, arguments);
  };
}();

var rsaEncrypt = function () {
  var _ref8 = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee8(text, publicKey) {
    var key, encrypted;
    return regeneratorRuntime.wrap(function _callee8$(_context8) {
      while (1) {
        switch (_context8.prev = _context8.next) {
          case 0:
            key = new NodeRSA(publicKey);
            encrypted = key.encrypt(text, 'base64', 'utf8');
            return _context8.abrupt('return', encrypted);

          case 3:
          case 'end':
            return _context8.stop();
        }
      }
    }, _callee8, this);
  }));

  return function rsaEncrypt(_x9, _x10) {
    return _ref8.apply(this, arguments);
  };
}();

var rsaDecrypt = function () {
  var _ref9 = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee9(text, privateKey) {
    var key, decrypted;
    return regeneratorRuntime.wrap(function _callee9$(_context9) {
      while (1) {
        switch (_context9.prev = _context9.next) {
          case 0:
            key = new NodeRSA(privateKey);
            decrypted = key.decrypt(text, 'utf8');
            return _context9.abrupt('return', decrypted);

          case 3:
          case 'end':
            return _context9.stop();
        }
      }
    }, _callee9, this);
  }));

  return function rsaDecrypt(_x11, _x12) {
    return _ref9.apply(this, arguments);
  };
}();

var sha256Sign = function () {
  var _ref10 = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee10(text, privateKey) {
    var sign, signature;
    return regeneratorRuntime.wrap(function _callee10$(_context10) {
      while (1) {
        switch (_context10.prev = _context10.next) {
          case 0:
            sign = crypto.createSign('RSA-SHA256');
            _context10.next = 3;
            return processStream(sign, text, { from: 'utf8', to: 'utf8' });

          case 3:
            signature = sign.sign(privateKey, 'hex');
            return _context10.abrupt('return', signature);

          case 5:
          case 'end':
            return _context10.stop();
        }
      }
    }, _callee10, this);
  }));

  return function sha256Sign(_x13, _x14) {
    return _ref10.apply(this, arguments);
  };
}();

var sha256Verify = function () {
  var _ref11 = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee11(text, publicKey, signature) {
    var verify, isSignatureValid;
    return regeneratorRuntime.wrap(function _callee11$(_context11) {
      while (1) {
        switch (_context11.prev = _context11.next) {
          case 0:
            verify = crypto.createVerify('RSA-SHA256');
            _context11.next = 3;
            return processStream(verify, text, { from: 'utf8', to: 'utf8' });

          case 3:
            isSignatureValid = verify.verify(publicKey, signature, 'hex');
            return _context11.abrupt('return', isSignatureValid);

          case 5:
          case 'end':
            return _context11.stop();
        }
      }
    }, _callee11, this);
  }));

  return function sha256Verify(_x15, _x16, _x17) {
    return _ref11.apply(this, arguments);
  };
}();

var md5 = function () {
  var _ref12 = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee12(text) {
    var hash, hashValue;
    return regeneratorRuntime.wrap(function _callee12$(_context12) {
      while (1) {
        switch (_context12.prev = _context12.next) {
          case 0:
            hash = crypto.createHash('md5');
            _context12.next = 3;
            return processStream(hash, text, { from: 'utf8', to: 'hex' });

          case 3:
            hashValue = _context12.sent;
            return _context12.abrupt('return', hashValue);

          case 5:
          case 'end':
            return _context12.stop();
        }
      }
    }, _callee12, this);
  }));

  return function md5(_x18) {
    return _ref12.apply(this, arguments);
  };
}();

var sha1 = function () {
  var _ref13 = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee13(text) {
    var hash, hashValue;
    return regeneratorRuntime.wrap(function _callee13$(_context13) {
      while (1) {
        switch (_context13.prev = _context13.next) {
          case 0:
            hash = crypto.createHash('sha1');
            _context13.next = 3;
            return processStream(hash, text, { from: 'utf8', to: 'hex' });

          case 3:
            hashValue = _context13.sent;
            return _context13.abrupt('return', hashValue);

          case 5:
          case 'end':
            return _context13.stop();
        }
      }
    }, _callee13, this);
  }));

  return function sha1(_x19) {
    return _ref13.apply(this, arguments);
  };
}();

var sha256 = function () {
  var _ref14 = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee14(text) {
    var hash, hashValue;
    return regeneratorRuntime.wrap(function _callee14$(_context14) {
      while (1) {
        switch (_context14.prev = _context14.next) {
          case 0:
            hash = crypto.createHash('sha256');
            _context14.next = 3;
            return processStream(hash, text, { from: 'utf8', to: 'hex' });

          case 3:
            hashValue = _context14.sent;
            return _context14.abrupt('return', hashValue);

          case 5:
          case 'end':
            return _context14.stop();
        }
      }
    }, _callee14, this);
  }));

  return function sha256(_x20) {
    return _ref14.apply(this, arguments);
  };
}();

var sha1hmac = function () {
  var _ref15 = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee15(text, password) {
    var hmac, hashValue;
    return regeneratorRuntime.wrap(function _callee15$(_context15) {
      while (1) {
        switch (_context15.prev = _context15.next) {
          case 0:
            hmac = crypto.createHmac('sha1', password);
            _context15.next = 3;
            return processStream(hmac, text, { from: 'utf8', to: 'hex' });

          case 3:
            hashValue = _context15.sent;
            return _context15.abrupt('return', hashValue);

          case 5:
          case 'end':
            return _context15.stop();
        }
      }
    }, _callee15, this);
  }));

  return function sha1hmac(_x21, _x22) {
    return _ref15.apply(this, arguments);
  };
}();

var sha256hmac = function () {
  var _ref16 = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee16(text, password) {
    var hmac, hashValue;
    return regeneratorRuntime.wrap(function _callee16$(_context16) {
      while (1) {
        switch (_context16.prev = _context16.next) {
          case 0:
            hmac = crypto.createHmac('sha256', password);
            _context16.next = 3;
            return processStream(hmac, text, { from: 'utf8', to: 'hex' });

          case 3:
            hashValue = _context16.sent;
            return _context16.abrupt('return', hashValue);

          case 5:
          case 'end':
            return _context16.stop();
        }
      }
    }, _callee16, this);
  }));

  return function sha256hmac(_x23, _x24) {
    return _ref16.apply(this, arguments);
  };
}();

var crypto2 = {
  createPassword: createPassword,
  createKeyPair: createKeyPair,
  readPrivateKey: readPrivateKey,
  readPublicKey: readPublicKey,

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