/* This Source Code Form is subject to the terms of the Mozilla Public
* License, v. 2.0. If a copy of the MPL was not distributed with this
* file, You can obtain one at http://mozilla.org/MPL/2.0/. */

'use strict';

var PREFIX_NAME = 'identity.mozilla.com/picl/v1/';
// hash length is 32 because only that's SHA256 length
var HASH_LENGTH = 32;

// This should be equivalent to:
// var emptyKey = new Uint8Array(0);
// According to FIPS-198-1, Section 4, step 3. Sadly it isn't.
var emptyKey = new Uint8Array(HASH_LENGTH);


// Convert an ArrayBufferView to a hex string
function abv2hex(abv) {
  var b = new Uint8Array(abv.buffer, abv.byteOffset, abv.byteLength);
  var hex = "";
  for (var i=0; i <b.length; ++i) {
    var zeropad = (b[i] < 0x10) ? "0" : "";
    hex += zeropad + b[i].toString(16);
  }
  return hex;
}

// Convert a hex string to an ArrayBufferView
function hex2abv(hex) {
  if (hex.length % 2 !== 0) {
    hex = "0" + hex;
  }
  var abv = new Uint8Array(hex.length / 2);
  for (var i=0; i<abv.length; ++i) {
    abv[i] = parseInt(hex.substr(2*i, 2), 16);
  }
  return abv;
}


function concatU8Array(buffer1, buffer2) {
  var aux = new Uint8Array(buffer1.byteLength + buffer2.byteLength);
  aux.set(new Uint8Array(buffer1), 0);
  aux.set(new Uint8Array(buffer2), buffer1.byteLength);
  return aux;
};

/**
 * hkdf - The HMAC-based Key Derivation Function
 * based on https://github.com/mozilla/node-hkdf
 *
 * @class hkdf
 * @param {bitArray} ikm Initial keying material
 * @param {bitArray} info Key derivation data
 * @param {bitArray} salt Salt
 * @param {integer} length Length of the derived key in bytes
 * @return promise object- It will resolve with `output` data
 */
function hkdf(ikm, info, salt, length) {
  // Some things global to the algorithm
  var tEncoder = new TextEncoder('utf8');
  var numBlocks = Math.ceil(length / HASH_LENGTH);
  var subtle = window.crypto.subtle;
  var alg = {
    name: "HMAC",
    hash: "SHA-256"
  };

  // Imports a raw key
  function doImportKey(rawKey) {
    return subtle.importKey('raw', rawKey, alg, false, ['sign']);
  }

  // 'signs' the tbsData with hmacKey
  function doHMAC(tbsData, hmacKey) {
    return subtle.sign(alg.name, hmacKey, tbsData);
  }

  // Do the hashing part of a HDKF round
  function doHKDFRound(roundNumber, prevDigest, prevOutput, hkdfKey) {
    // Do the data accumulating part of an HKDF round. Also, it
    // checks if there are still more rounds left and fires the next
    // Or just finishes the process calling the callback.
    function addToOutput(digest) {
      var output = prevOutput + abv2hex(digest);

      if (++roundNumber <= numBlocks) {
        return doHKDFRound(roundNumber, digest, output, hkdfKey);
      } else {
        return new Promise(function(resolve, reject) {
          var truncated = hex2abv(output).subarray(0, length);
          resolve(truncated);
        });
      }
    }

    var input = concatU8Array(concatU8Array(prevDigest, info),
                              tEncoder.encode(String.fromCharCode(roundNumber)));
    return doHMAC(input, hkdfKey).then(addToOutput);
  }


  return doImportKey(salt). // Imports the initial key
    then(doHMAC.bind(undefined, ikm)). // Generates the key deriving key
    then(doImportKey). // Imports the key deriving key
    then(doHKDFRound.bind(undefined, 1, new Uint8Array(0), ''));
    // Launches the first HKDF round
}

/**
* @class hawkCredentials
* @method deriveHawkCredentials
* @param {String} tokenHex
* @param {String} context
* @param {int} size
* @returns {Promise}
*/
function deriveHawkCredentials(tokenHex, context, size, callback) {
  var token = hex2abv(tokenHex);
  var info = new TextEncoder('utf8').encode(PREFIX_NAME + context);

  hkdf(token, info, emptyKey, size || 3 * 32).then(function(out) {
    var authKey = out.subarray(32, 64);
    var bundleKey = out.subarray(64);
    callback({
      algorithm: 'sha256',
      id: abv2hex(out.subarray(0, 32)),
      key: abv2hex(authKey),
      bundleKey: bundleKey
    });
  });
}
