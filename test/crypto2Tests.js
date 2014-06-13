'use strict';

var assert = require('node-assertthat'),
    ursa = require('ursa');

var crypto2 = require('../lib/crypto2');

suite('crypto2', function () {
  suite('createPassword', function () {
    test('returns a new random password with 32 bytes length.', function (done) {
      crypto2.createPassword(function (err, password) {
        assert.that(err, is.null());
        assert.that(password.length, is.equalTo(32));
        done();
      });
    });
  });

  suite('createKeyPair', function () {
    test('returns a new key pair.', function (done) {
      crypto2.createKeyPair(function (err, privateKey, publicKey) {
        assert.that(err, is.null());
        assert.that(ursa.isPrivateKey(ursa.coerceKey(privateKey)), is.true());
        assert.that(ursa.isPublicKey(ursa.coerceKey(publicKey)), is.true());
        done();
      });
    });
  });

  suite('readPrivateKey', function () {
    test('reads a private key from a .pem file.', function (done) {
      crypto2.readPrivateKey('./test/key.pem', function (err, key) {
        assert.that(err, is.null());
        assert.that(ursa.isPrivateKey(key), is.true());
        done();
      });
    });
  });

  suite('readPublicKey', function () {
    test('reads a public key from a .pub file.', function (done) {
      crypto2.readPublicKey('./test/key.pub', function (err, key) {
        assert.that(err, is.null());
        assert.that(ursa.isPublicKey(key), is.true());
        done();
      });
    });
  });

  suite('encrypt', function () {
    suite('aes256cbc', function () {
      test('encrypts using the AES 256 CBC encryption standard.', function (done) {
        crypto2.encrypt.aes256cbc('the native web', 'secret', function (err, encryptedText) {
          assert.that(err, is.null());
          assert.that(encryptedText, is.equalTo('6c9ae06e9cd536bf38d0f551f8150065'));
          done();
        });
      });
    });

    suite('rsa', function () {
      test('encrypts using the RSA encryption standard.', function (done) {
        crypto2.readPublicKey('./test/key.pub', function (err, publicKey) {
          assert.that(err, is.null());
          crypto2.encrypt.rsa('the native web', publicKey, function (err, encrypted) {
            assert.that(err, is.null());
            crypto2.readPrivateKey('./test/key.pem', function (err, privateKey) {
              assert.that(err, is.null());
              crypto2.decrypt.rsa(encrypted, privateKey, function (err, decrypted) {
                assert.that(err, is.null());
                assert.that(decrypted, is.equalTo('the native web'));
                done();
              });
            });
          });
        });
      });
    });

    test('defaults to AES 256 CBC.', function (done) {
      crypto2.encrypt('the native web', 'secret', function (err, actualEncryptedText) {
        assert.that(err, is.null());
        crypto2.encrypt.aes256cbc('the native web', 'secret', function (err, expectecEncryptedText) {
          assert.that(err, is.null());
          assert.that(actualEncryptedText, is.equalTo(expectecEncryptedText));
          done();
        });
      });
    });
  });

  suite('decrypt', function () {
    suite('aes256cbc', function () {
      test('decrypts using the AES 256 CBC encryption standard.', function (done) {
        crypto2.decrypt.aes256cbc('6c9ae06e9cd536bf38d0f551f8150065', 'secret', function (err, decryptedText) {
          assert.that(err, is.null());
          assert.that(decryptedText, is.equalTo('the native web'));
          done();
        });
      });
    });

    suite('rsa', function () {
      test('decrypts using the RSA encryption standard.', function (done) {
        crypto2.readPublicKey('./test/key.pub', function (err, publicKey) {
          assert.that(err, is.null());
          crypto2.encrypt.rsa('the native web', publicKey, function (err, encrypted) {
            assert.that(err, is.null());
            crypto2.readPrivateKey('./test/key.pem', function (err, privateKey) {
              assert.that(err, is.null());
              crypto2.decrypt.rsa(encrypted, privateKey, function (err, decrypted) {
                assert.that(err, is.null());
                assert.that(decrypted, is.equalTo('the native web'));
                done();
              });
            });
          });
        });
      });
    });

    test('defaults to AES 256 CBC.', function (done) {
      crypto2.decrypt('6c9ae06e9cd536bf38d0f551f8150065', 'secret', function (err, actualDecryptedText) {
        assert.that(err, is.null());
        crypto2.decrypt.aes256cbc('6c9ae06e9cd536bf38d0f551f8150065', 'secret', function (err, expectedDecryptedText) {
          assert.that(err, is.null());
          assert.that(actualDecryptedText, is.equalTo(expectedDecryptedText));
          done();
        });
      });
    });
  });

  suite('sign', function () {
    suite('sha256', function () {
      test('signs using the SHA256 signing standard.', function (done) {
        crypto2.readPrivateKey('./test/key.pem', function (err, privateKey) {
          assert.that(err, is.null());
          crypto2.sign.sha256('the native web', privateKey, function (err, signature) {
            assert.that(err, is.null());
            assert.that(signature, is.equalTo('6c20e04d7dca6eeff43a7a618776d91d121204c698426b6d5f809d631be8d09ca02643af36f324008afc0d4e1cf0ba137c976afaa74bd559c1e1201694312ad98ae17a66de04812b1efe68c5b1c057f719ff111a938980e11292933074101fd5141d494c13484f45b1f710a2c041ae4ada27667ac3855492b49d77a0a64e6c406925e68b7ed55298ef4387e2884f3a021c6f76b4146607f32d657d070e78e86d43d068b17cca9873a666f572b0d078525446b7dd1ef30ae20b91161a5a9bab7123b56c35fac7d3ce9b749c524c62b5b3eb8e76445c9dfd80370daed8d53a4efdab0acb14a4875758b708b2da75a070db84ebd4bd4f3a073424df214aaf0b9914'));
            done();
          });
        });
      });
    });

    test('defaults to SHA256.', function (done) {
      crypto2.readPrivateKey('./test/key.pem', function (err, privateKey) {
        assert.that(err, is.null());
        crypto2.sign('the native web', privateKey, function (err, actualSignature) {
          assert.that(err, is.null());
          crypto2.sign.sha256('the native web', privateKey, function (err, expectedSignature) {
            assert.that(err, is.null());
            assert.that(actualSignature, is.equalTo(expectedSignature));
            done();
          });
        });
      });
    });
  });

  suite('verify', function () {
    suite('sha256', function () {
      test('verifies using the SHA256 signing standard.', function (done) {
        crypto2.readPublicKey('./test/key.pub', function (err, publicKey) {
          assert.that(err, is.null());
          crypto2.verify.sha256('the native web', publicKey, '6c20e04d7dca6eeff43a7a618776d91d121204c698426b6d5f809d631be8d09ca02643af36f324008afc0d4e1cf0ba137c976afaa74bd559c1e1201694312ad98ae17a66de04812b1efe68c5b1c057f719ff111a938980e11292933074101fd5141d494c13484f45b1f710a2c041ae4ada27667ac3855492b49d77a0a64e6c406925e68b7ed55298ef4387e2884f3a021c6f76b4146607f32d657d070e78e86d43d068b17cca9873a666f572b0d078525446b7dd1ef30ae20b91161a5a9bab7123b56c35fac7d3ce9b749c524c62b5b3eb8e76445c9dfd80370daed8d53a4efdab0acb14a4875758b708b2da75a070db84ebd4bd4f3a073424df214aaf0b9914', function (err, isSignatureValid) {
            assert.that(err, is.null());
            assert.that(isSignatureValid, is.equalTo(true));
            done();
          });
        });
      });
    });

    test('defaults to SHA256.', function (done) {
      crypto2.readPublicKey('./test/key.pub', function (err, publicKey) {
        assert.that(err, is.null());
        crypto2.verify('the native web', publicKey, '6c20e04d7dca6eeff43a7a618776d91d121204c698426b6d5f809d631be8d09ca02643af36f324008afc0d4e1cf0ba137c976afaa74bd559c1e1201694312ad98ae17a66de04812b1efe68c5b1c057f719ff111a938980e11292933074101fd5141d494c13484f45b1f710a2c041ae4ada27667ac3855492b49d77a0a64e6c406925e68b7ed55298ef4387e2884f3a021c6f76b4146607f32d657d070e78e86d43d068b17cca9873a666f572b0d078525446b7dd1ef30ae20b91161a5a9bab7123b56c35fac7d3ce9b749c524c62b5b3eb8e76445c9dfd80370daed8d53a4efdab0acb14a4875758b708b2da75a070db84ebd4bd4f3a073424df214aaf0b9914', function (err, actualIsSignatureValid) {
          assert.that(err, is.null());
          crypto2.verify.sha256('the native web', publicKey, '6c20e04d7dca6eeff43a7a618776d91d121204c698426b6d5f809d631be8d09ca02643af36f324008afc0d4e1cf0ba137c976afaa74bd559c1e1201694312ad98ae17a66de04812b1efe68c5b1c057f719ff111a938980e11292933074101fd5141d494c13484f45b1f710a2c041ae4ada27667ac3855492b49d77a0a64e6c406925e68b7ed55298ef4387e2884f3a021c6f76b4146607f32d657d070e78e86d43d068b17cca9873a666f572b0d078525446b7dd1ef30ae20b91161a5a9bab7123b56c35fac7d3ce9b749c524c62b5b3eb8e76445c9dfd80370daed8d53a4efdab0acb14a4875758b708b2da75a070db84ebd4bd4f3a073424df214aaf0b9914', function (err, expectedIsSignatureValid) {
            assert.that(err, is.null());
            assert.that(actualIsSignatureValid, is.equalTo(expectedIsSignatureValid));
            done();
          });
        });
      });
    });
  });

  suite('hash', function () {
    suite('md5', function () {
      test('calculates the MD5 hash value.', function (done) {
        crypto2.hash.md5('the native web', function (err, hashedText) {
          assert.that(err, is.null());
          assert.that(hashedText, is.equalTo('4e8ba2e64931c64b63f4dc8d90e1dc7c'));
          done();
        });
      });
    });

    suite('sha1', function () {
      test('calculates the SHA1 hash value.', function (done) {
        crypto2.hash.sha1('the native web', function (err, hashedText) {
          assert.that(err, is.null());
          assert.that(hashedText, is.equalTo('cc762e69089ee2393b061ab26a005319bda94744'));
          done();
        });
      });
    });

    test('defaults to SHA1.', function (done) {
      crypto2.hash('the native web', function (err, actualHashedText) {
        assert.that(err, is.null());
        crypto2.hash.sha1('the native web', function (err, expectedHashedText) {
          assert.that(err, is.null());
          assert.that(actualHashedText, is.equalTo(expectedHashedText));
          done();
        });
      });
    });
  });

  suite('hmac', function () {
    suite('sha1', function () {
      test('calculates the SHA1-based HMAC value.', function (done) {
        crypto2.hmac.sha1('the native web', 'secret', function (err, hmacedText) {
          assert.that(err, is.null());
          assert.that(hmacedText, is.equalTo('c9a6cdb2d350820e76a14f4f9a6392990ce1982a'));
          done();
        });
      });
    });

    test('defaults to SHA1.', function (done) {
      crypto2.hmac('the native web', 'secret', function (err, actualHmacedText) {
        assert.that(err, is.null());
        crypto2.hmac.sha1('the native web', 'secret', function (err, expectedHmacedText) {
          assert.that(err, is.null());
          assert.that(actualHmacedText, is.equalTo(expectedHmacedText));
          done();
        });
      });
    });
  });
});
