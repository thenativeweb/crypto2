'use strict';

var crypto2 = require('../lib/crypto2');

var text = 'the native web';

var encryptedText,
    encryptedKey,
    decryptedKey,
    decryptedText;

console.log('original : ' + text);

crypto2.readPublicKey(__dirname + '/key.pub', function (publicKey) {
  crypto2.createPassword(function (password) {
    encryptedText = crypto2.encrypt(text, password);
    encryptedKey = crypto2.encrypt.rsa(password, publicKey);

    console.log('encrypted: ' + encryptedText);

    crypto2.readPrivateKey(__dirname + '/key.pem', function (privateKey) {
      decryptedKey = crypto2.decrypt.rsa(encryptedKey, privateKey);
      decryptedText = crypto2.decrypt(encryptedText, decryptedKey);

      console.log('decrypted: ' + decryptedText);
    });
  });
});