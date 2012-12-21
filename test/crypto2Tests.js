var assert = require('node-assertthat');

var crypto2 = require('../lib/crypto2');

suite('crypto2', function () {
  suite('hash', function () {
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