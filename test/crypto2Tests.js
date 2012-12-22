'use strict';

var assert = require('node-assertthat'),
    ursa = require('ursa');

var crypto2 = require('../lib/crypto2');

suite('crypto2', function () {
  suite('readKey', function () {
    test('reads a key from a .pem file.', function (done) {
      crypto2.readKey('./test/key.pem', function (key) {
        assert.that(ursa.isPrivateKey(key), is.equalTo(true));
        done();
      });
    });
  });

  suite('encrypt', function () {
    suite('aes256cbc', function () {
      test('encrypts using the AES 256 CBC encryption standard.', function () {
        assert.that(crypto2.encrypt.aes256cbc('the native web', 'secret'), is.equalTo('6c9ae06e9cd536bf38d0f551f8150065'));
      });
    });

    test('defaults to AES 256 CBC.', function () {
      assert.that(crypto2.encrypt('the native web', 'secret'), is.equalTo(crypto2.encrypt.aes256cbc('the native web', 'secret')));
    });
  });

  suite('decrypt', function () {
    suite('aes256cbc', function () {
      test('decrypts using the AES 256 CBC encryption standard.', function () {
        assert.that(crypto2.decrypt.aes256cbc('6c9ae06e9cd536bf38d0f551f8150065', 'secret'), is.equalTo('the native web'));
      });
    });

    test('defaults to AES 256 CBC.', function () {
      assert.that(crypto2.decrypt('6c9ae06e9cd536bf38d0f551f8150065', 'secret'), is.equalTo(crypto2.decrypt.aes256cbc('6c9ae06e9cd536bf38d0f551f8150065', 'secret')));
    });
  });

  suite('sign', function () {
    suite('sha256', function () {
      test('signs using the SHA256 signing standard.', function (done) {
        crypto2.readKey('./test/key.pem', function (privateKey) {
          assert.that(crypto2.sign.sha256('the native web', privateKey), is.equalTo('6c20e04d7dca6eeff43a7a618776d91d121204c698426b6d5f809d631be8d09ca02643af36f324008afc0d4e1cf0ba137c976afaa74bd559c1e1201694312ad98ae17a66de04812b1efe68c5b1c057f719ff111a938980e11292933074101fd5141d494c13484f45b1f710a2c041ae4ada27667ac3855492b49d77a0a64e6c406925e68b7ed55298ef4387e2884f3a021c6f76b4146607f32d657d070e78e86d43d068b17cca9873a666f572b0d078525446b7dd1ef30ae20b91161a5a9bab7123b56c35fac7d3ce9b749c524c62b5b3eb8e76445c9dfd80370daed8d53a4efdab0acb14a4875758b708b2da75a070db84ebd4bd4f3a073424df214aaf0b9914'));
          done();
        });
      });
    });

    test('defaults to SHA256.', function (done) {
      crypto2.readKey('./test/key.pem', function (privateKey) {
        assert.that(crypto2.sign('the native web', privateKey), is.equalTo(crypto2.sign.sha256('the native web', privateKey)));
        done();
      });
    });
  });

  suite('verify', function () {
    suite('sha256', function () {
      test('verifies using the SHA256 signing standard.', function (done) {
        crypto2.readKey('./test/key.pem', function (publicKey) {
          assert.that(crypto2.verify.sha256('the native web', publicKey, '6c20e04d7dca6eeff43a7a618776d91d121204c698426b6d5f809d631be8d09ca02643af36f324008afc0d4e1cf0ba137c976afaa74bd559c1e1201694312ad98ae17a66de04812b1efe68c5b1c057f719ff111a938980e11292933074101fd5141d494c13484f45b1f710a2c041ae4ada27667ac3855492b49d77a0a64e6c406925e68b7ed55298ef4387e2884f3a021c6f76b4146607f32d657d070e78e86d43d068b17cca9873a666f572b0d078525446b7dd1ef30ae20b91161a5a9bab7123b56c35fac7d3ce9b749c524c62b5b3eb8e76445c9dfd80370daed8d53a4efdab0acb14a4875758b708b2da75a070db84ebd4bd4f3a073424df214aaf0b9914'), is.equalTo(true));
          done();
        });
      });
    });

    test('defaults to SHA256.', function (done) {
      crypto2.readKey('./test/key.pem', function (publicKey) {
        assert.that(crypto2.verify('the native web', publicKey, '6c20e04d7dca6eeff43a7a618776d91d121204c698426b6d5f809d631be8d09ca02643af36f324008afc0d4e1cf0ba137c976afaa74bd559c1e1201694312ad98ae17a66de04812b1efe68c5b1c057f719ff111a938980e11292933074101fd5141d494c13484f45b1f710a2c041ae4ada27667ac3855492b49d77a0a64e6c406925e68b7ed55298ef4387e2884f3a021c6f76b4146607f32d657d070e78e86d43d068b17cca9873a666f572b0d078525446b7dd1ef30ae20b91161a5a9bab7123b56c35fac7d3ce9b749c524c62b5b3eb8e76445c9dfd80370daed8d53a4efdab0acb14a4875758b708b2da75a070db84ebd4bd4f3a073424df214aaf0b9914'), is.equalTo(crypto2.verify.sha256('the native web', publicKey, '6c20e04d7dca6eeff43a7a618776d91d121204c698426b6d5f809d631be8d09ca02643af36f324008afc0d4e1cf0ba137c976afaa74bd559c1e1201694312ad98ae17a66de04812b1efe68c5b1c057f719ff111a938980e11292933074101fd5141d494c13484f45b1f710a2c041ae4ada27667ac3855492b49d77a0a64e6c406925e68b7ed55298ef4387e2884f3a021c6f76b4146607f32d657d070e78e86d43d068b17cca9873a666f572b0d078525446b7dd1ef30ae20b91161a5a9bab7123b56c35fac7d3ce9b749c524c62b5b3eb8e76445c9dfd80370daed8d53a4efdab0acb14a4875758b708b2da75a070db84ebd4bd4f3a073424df214aaf0b9914')));
        done();
      });
    });
  });

  suite('hash', function () {
    suite('md5', function () {
      test('calculates the MD5 hash value.', function () {
        assert.that(crypto2.hash.md5('the native web'), is.equalTo('4e8ba2e64931c64b63f4dc8d90e1dc7c'));
      });
    });

    suite('sha1', function () {
      test('calculates the SHA1 hash value.', function () {
        assert.that(crypto2.hash.sha1('the native web'), is.equalTo('cc762e69089ee2393b061ab26a005319bda94744'));
      });
    });

    test('defaults to SHA1.', function () {
      assert.that(crypto2.hash('the native web'), is.equalTo(crypto2.hash.sha1('the native web')));
    });
  });
});