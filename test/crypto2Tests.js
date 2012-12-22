'use strict';

var assert = require('node-assertthat');

var crypto2 = require('../lib/crypto2');

suite('crypto2', function () {
  suite('readKey', function () {
    test('reads a key from a .pem file.', function (done) {
      crypto2.readKey('./test/keys/key.pem', function (key) {
        assert.that(key, is.equalTo(
          '-----BEGIN RSA PRIVATE KEY-----\n' +
          'MIIEowIBAAKCAQEAmETpbSyDAL58IvRm6GYwcav4wbnbIl5q0vhApJUdWj7w1p0Q\n' +
          'MQTxc6WlNWrdiQ4z4mNEo0EhqPWTLLfay/hyMZLwwKNSzN+ZKx55bggms5okqFed\n' +
          '+gtdbDb1wN27YFdBcF4zYY7GE8Np4Rq2spEdPyYQGZyr0nz9NwC0SJNFrL4SUavq\n' +
          'aPgz6TYa/YrjL4oy09SUBwTmoqSzWIeSBMGWsrYh8S1EVZ49VZlBJB3ZcjztKsS1\n' +
          'Q5EzZZd4lpoYA2Wodi0+Szk02lns5fj0EatfpQsq1+LFVgWGc3FQmTlvcIAQtTms\n' +
          'ePe33Je0/ogSL9zuOcxnutiS4rXEGyX45GEG6QIDAQABAoIBAACCQnFt86Yd/NY1\n' +
          'EN738HOAyp0DHPtZa2v3Dmg+Y1G44h8leTdgt9nWFN4/1CuwE3ZPNJyDDDS/VVWR\n' +
          '67ZAx0jpH8rVAOLUYHOnb2pxtodlHXg+irWaMh65dErHsueYgwx4FB3gV0MbpQ/u\n' +
          'gevI1lsuqmEbh+t1JXd4liGj9FimbKFq89Y5cjw66QCfk+T2O1Eqt9jhoWoLYHuk\n' +
          'U32ZBq4gNwSuJfEAPc9VWdFjABKAOOzZa1OIfYSguhjU60Yi4auUknzNgVC0Ul9J\n' +
          'yr2KoRPJ8h+CH6DfYUyAJkxBb6GuHWZ1u36z1IZl7IKMwc9GfUqQdZ0de3hBJ7Li\n' +
          'lQQWwC0CgYEAyAh6yd5kVANdSYwThxq4X10y92+pcJcTCLI88FfhYA7gd0g/fcqn\n' +
          'LAzHItSkrgtj8N1QQsKl6mUOKU/7tZyDWrHmCPWW6IFHswqfy0NEBfmWMxty2zMe\n' +
          'yH6ZiUXlocYZUFwxkSIeHXIgqh1a+CYmDbSKWHVey4qpHo8ZGV9CUBMCgYEAwt9O\n' +
          'DaGgMhpHmLXBkTjo4QZe9xGJ36FwUcmVShfQsTO880Hd2j2Zxcy5ZMES7zMRxBv0\n' +
          '05UBb3B4GNnjOpfMUecQMDhrODsaUbES/SpRlfdpYZRnkng5iX5BOD1tpvRXdgg4\n' +
          'Fie2RNDO0jddxwEundPefaZi4omVd+k86mzYRJMCgYAqGWbGT7Dr4Z1jmkCN4bjG\n' +
          'EVZlrzGJCbKu1NxwdP5w+hCR6jm6nskaQ0Ix+XEDVFBfZCS9ODw1HbmiRjwil+Mp\n' +
          'VmGkpxNwsazGaMkCvZB2dXYAIZnFuneTGNn1gyl2J7wyJoUkF3shFWD8jJsVuOmv\n' +
          'XrzzKxidW/yF+vX8WgkZ0wKBgQCJSPwaClVrNqxd3x4hCvC1JuHcOVTiYT9ZvyQX\n' +
          'cLOrQwHIdgyvZVphyRqK6qJGNbo8aF2QeZbrRVa2WzoD21EsGhaDghu3H5wpFRCF\n' +
          'njyf5A8vmXdl7qDKRlH4Jv6K8fRzyNKKeSulS12JJ0w/mIuY0NwbtQ5Q/hB4y64I\n' +
          'kOnDVQKBgBvMDcJfYSve0iGkFgNP/6g0oju3ia4ovOciZmnasOgF0gXIHIAx0//b\n' +
          'RhtnQHjSQLBhlodSaTHt4aOLQsAhoNyqH7JjloOdZ4fXA3KyEjIDTJ2x1nPkLNHc\n' +
          'UAot7YU4JukFEC8W8xNmALcLIxa76fM75kAvq4iyvS/j8XvWbdhC\n' +
          '-----END RSA PRIVATE KEY-----\n'));
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
    suite('rsasha256', function () {
      test('signs using the RSA-SHA256 signing standard.', function (done) {
        crypto2.readKey('./test/keys/key.pem', function (privateKey) {
          assert.that(crypto2.sign.rsasha256('the native web', privateKey), is.equalTo('6c20e04d7dca6eeff43a7a618776d91d121204c698426b6d5f809d631be8d09ca02643af36f324008afc0d4e1cf0ba137c976afaa74bd559c1e1201694312ad98ae17a66de04812b1efe68c5b1c057f719ff111a938980e11292933074101fd5141d494c13484f45b1f710a2c041ae4ada27667ac3855492b49d77a0a64e6c406925e68b7ed55298ef4387e2884f3a021c6f76b4146607f32d657d070e78e86d43d068b17cca9873a666f572b0d078525446b7dd1ef30ae20b91161a5a9bab7123b56c35fac7d3ce9b749c524c62b5b3eb8e76445c9dfd80370daed8d53a4efdab0acb14a4875758b708b2da75a070db84ebd4bd4f3a073424df214aaf0b9914'));
          done();
        });
      });
    });

    test('defaults to RSA-SHA256.', function (done) {
      crypto2.readKey('./test/keys/key.pem', function (privateKey) {
        assert.that(crypto2.sign('the native web', privateKey), is.equalTo(crypto2.sign.rsasha256('the native web', privateKey)));
        done();
      });
    });
  });

  suite('verify', function () {
    suite('rsasha256', function () {
      test('verifies using the RSA-SHA256 signing standard.', function (done) {
        crypto2.readKey('./test/keys/cert.pem', function (publicKey) {
          assert.that(crypto2.verify.rsasha256('the native web', publicKey, '6c20e04d7dca6eeff43a7a618776d91d121204c698426b6d5f809d631be8d09ca02643af36f324008afc0d4e1cf0ba137c976afaa74bd559c1e1201694312ad98ae17a66de04812b1efe68c5b1c057f719ff111a938980e11292933074101fd5141d494c13484f45b1f710a2c041ae4ada27667ac3855492b49d77a0a64e6c406925e68b7ed55298ef4387e2884f3a021c6f76b4146607f32d657d070e78e86d43d068b17cca9873a666f572b0d078525446b7dd1ef30ae20b91161a5a9bab7123b56c35fac7d3ce9b749c524c62b5b3eb8e76445c9dfd80370daed8d53a4efdab0acb14a4875758b708b2da75a070db84ebd4bd4f3a073424df214aaf0b9914'), is.equalTo(true));
          done();
        });
      });
    });

    test('defaults to RSA-SHA256.', function (done) {
      crypto2.readKey('./test/keys/cert.pem', function (publicKey) {
        assert.that(crypto2.verify('the native web', publicKey, '6c20e04d7dca6eeff43a7a618776d91d121204c698426b6d5f809d631be8d09ca02643af36f324008afc0d4e1cf0ba137c976afaa74bd559c1e1201694312ad98ae17a66de04812b1efe68c5b1c057f719ff111a938980e11292933074101fd5141d494c13484f45b1f710a2c041ae4ada27667ac3855492b49d77a0a64e6c406925e68b7ed55298ef4387e2884f3a021c6f76b4146607f32d657d070e78e86d43d068b17cca9873a666f572b0d078525446b7dd1ef30ae20b91161a5a9bab7123b56c35fac7d3ce9b749c524c62b5b3eb8e76445c9dfd80370daed8d53a4efdab0acb14a4875758b708b2da75a070db84ebd4bd4f3a073424df214aaf0b9914'), is.equalTo(crypto2.verify.rsasha256('the native web', publicKey, '6c20e04d7dca6eeff43a7a618776d91d121204c698426b6d5f809d631be8d09ca02643af36f324008afc0d4e1cf0ba137c976afaa74bd559c1e1201694312ad98ae17a66de04812b1efe68c5b1c057f719ff111a938980e11292933074101fd5141d494c13484f45b1f710a2c041ae4ada27667ac3855492b49d77a0a64e6c406925e68b7ed55298ef4387e2884f3a021c6f76b4146607f32d657d070e78e86d43d068b17cca9873a666f572b0d078525446b7dd1ef30ae20b91161a5a9bab7123b56c35fac7d3ce9b749c524c62b5b3eb8e76445c9dfd80370daed8d53a4efdab0acb14a4875758b708b2da75a070db84ebd4bd4f3a073424df214aaf0b9914')));
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