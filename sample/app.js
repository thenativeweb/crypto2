var crypto2 = require('../lib/crypto2');

var text = 'the native web';

var encryptedText,
    encryptedKey,
    decryptedKey,
    decryptedText;

console.log('original text: ' + text);

crypto2.readPublicKey(__dirname + '/../test/key.pub', function (publicKey) {
  crypto2.createPassword(function (password) {
    encryptedText = crypto2.encrypt(text, password);
    encryptedKey = crypto2.encrypt.rsa(password, publicKey);

    console.log('encryptedText: ' + encryptedText);

    crypto2.readPrivateKey(__dirname + '/../test/key.pem', function (privateKey) {
      decryptedKey = crypto2.decrypt.rsa(encryptedKey, privateKey);
      decryptedText = crypto2.decrypt(encryptedText, decryptedKey);

      console.log('decryptedText: ' + decryptedText);
    });
  });
});