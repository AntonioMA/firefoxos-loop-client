'use strict';

var TOKEN_TEST = "Trying to use webcrypto implementation";
window.useSJCLCrypto = !window.crypto.subtle;
if (window.useSJCLCrypto) {
  suite('Hawk library with web crypto >', function() {
    test('Webcrypto is *NOT* available', function() {});
  });
} else {
  require('unit/hawk_test_common.js');
}


