var assert = require('node-assertthat');

var crypto2 = require('../lib/crypto2');

suite('crypto2', function () {
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