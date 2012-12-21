# crypto2

crypto2 is a convenience wrapper around Node.js' crypto module.

## Installation

At the moment, installation of this module must be made manually.

## Quick start

The first thing you need to do is to integrate crypto2 into your application. For that add a reference to the `crypto2` module.

```javascript
var crypto2 = require('crypto2');
```

### Encrypting and decrypting

...

### Signing and verifying

...

### Hashing

To calculate the SHA1 hash value of a string call the `hash.sha1` function.

```javascript
var hash = crypto2.hash.sha1('the native web');
// => cc762e69089ee2393b061ab26a005319bda94744
```

If you want crypto2 to select a hash algorithm for you, call the `hash` function without any specific algorithm. This defaults to the SHA1 hash algorithm.

```javascript
var hash = crypto2.hash('the native web');
// => cc762e69089ee2393b061ab26a005319bda94744
```

## Running the tests

crypto2 has been developed using TDD. To run the tests, go to the folder where you have installed crypto2 to and run `npm test`. You need to have [mocha](https://github.com/visionmedia/mocha) installed.

    $ npm test