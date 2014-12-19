(function(window) {

  // Declare namespace
  window.hawk = {
    headerVersion: '1',

    utils: {
      now: () => new Date().getTime(),

      escapeHeaderAttribute: attribute => attribute.replace(/\\/g, '\\\\').replace(/\"/g, '\\"'),

      parseContentType: header =>
        (!header ? '' :
         header.split(';')[0].replace(/^\s+|\s+$/g, '').toLowerCase()),

      parseAuthorizationHeader: function (header, keys) {

        if (!header) {
          return null;
        }

        var headerParts = header.match(/^(\w+)(?:\s+(.*))?$/);       // Header: scheme[ something]
        if (!headerParts) {
          return null;
        }

        var scheme = headerParts[1];
        if (scheme.toLowerCase() !== 'hawk') {
          return null;
        }

        var attributesString = headerParts[2];
        if (!attributesString) {
          return null;
        }

        var attributes = {};
        var verify =
          attributesString.replace(/(\w+)="([^"\\]*)"\s*(?:,\s*|$)/g, function ($0, $1, $2) {

            // Check valid attribute names
            if (keys.indexOf($1) === -1) {
              return null;
            }

            // Allowed attribute value characters:
            // !#$%&'()*+,-./:;<=>?@[]^_`{|}~ and space, a-z, A-Z, 0-9
            if ($2.match(/^[ \w\!#\$%&'\(\)\*\+,\-\.\/\:;<\=>\?@\[\]\^`\{\|\}~]+$/) === null) {
              return null;
            }

            // Check for duplicates
            if (attributes.hasOwnProperty($1)) {
              return null;
            }

            attributes[$1] = $2;
            return '';
        });

        if (verify !== '') {
          return null;
        }

        return attributes;
      },

      randomString: function (size) {
        var randomSource = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
        var len = randomSource.length;

        var result = [];
        for (var i = 0; i < size; ++i) {
          result[i] = randomSource[Math.floor(Math.random() * len)];
        }

        return result.join('');
      },

      parseUri: function (input) {

        // Based on: parseURI 1.2.2
        // http://blog.stevenlevithan.com/archives/parseuri
        // (c) Steven Levithan <stevenlevithan.com>
        // MIT License
        var keys = [
          'source', 'protocol', 'authority', 'userInfo', 'user', 'password',
          'hostname', 'port', 'resource', 'relative', 'pathname', 'directory',
          'file', 'query', 'fragment'
        ];

        var uriRegex = /^(?:([^:\/?#]+):)?(?:\/\/((?:(([^:@]*)(?::([^:@]*))?)?@)?([^:\/?#]*)(?::(\d*))?))?(((((?:[^?#\/]*\/)*)([^?#]*))(?:\?([^#]*))?)(?:#(.*))?)/;
        var uriByNumber = uriRegex.exec(input);
        var uri = {};

        var i = 15;
        while (i--) {
          uri[keys[i]] = uriByNumber[i] || '';
        }

        if (uri.port === null ||
            uri.port === '') {
          uri.port = (uri.protocol.toLowerCase() === 'http' ? '80' : (uri.protocol.toLowerCase() === 'https' ? '443' : ''));
        }

        return uri;
      },

      generateNormalizedString: function (type, options) {
        var normalized = 'hawk.' + hawk.headerVersion + '.' + type + '\n' +
                          options.ts + '\n' +
                          options.nonce + '\n' +
                          (options.method || '').toUpperCase() + '\n' +
                          (options.resource || '') + '\n' +
                          options.host.toLowerCase() + '\n' +
                          options.port + '\n' +
                          (options.hash || '') + '\n';

        if (options.ext) {
          normalized += options.ext.replace('\\', '\\\\').replace('\n', '\\n');
        }

        normalized += '\n';

        if (options.app) {
          normalized += options.app + '\n' +
            (options.dlg || '') + '\n';
        }

        return normalized;
      }
    }


  };

  // Crypto related functions might need a external library, so let's
  // defer its fulfulling.
  window.hawk.crypto = new Promise(function(resolve, reject) {
    var hawk = window.hawk;
    var crypto = {};

    // This will store the fulfilled value for the window.hawkCredentials
    var hawkCredentials;

    crypto = {

      // Generate an Authorization header for a given request

      /*
       uri: 'http://example.com/resource?a=b'
       method: HTTP verb (e.g. 'GET', 'POST')
       options: {

       // Required
       credentials: {
       id: 'dh37fgj492je',
       key: 'aoijedoaijsdlaksjdl',
       algorithm: 'sha256'                                 // 'sha1', 'sha256'
       },

       // Optional
       ext: 'application-specific',                        // Application specific data sent via the ext attribute
       timestamp: Date.now() / 1000,                       // A pre-calculated timestamp in seconds
       nonce: '2334f34f',                                  // A pre-generated nonce
       localtimeOffsetMsec: 400,                           // Time offset to sync with server time (ignored if timestamp provided)
       payload: '{"some":"payload"}',                      // UTF-8 encoded string for body hash generation (ignored if hash provided)
       contentType: 'application/json',                    // Payload content-type (ignored if hash provided)
       hash: 'U4MKKSmiVxk37JCCrAVIjV=',                    // Pre-calculated payload hash
       app: '24s23423f34dx',                               // Oz application id
       dlg: '234sz34tww3sd'                                // Oz delegated-by application id
       }
       */

      getClientHeader: function (uri, method, options) {
        var result = {
          field: '',
          artifacts: {}
        };

        // Validate inputs

        if (!uri || (typeof uri !== 'string' && typeof uri !== 'object') ||
            !method || typeof method !== 'string' ||
            !options || typeof options !== 'object') {

          result.err = 'Invalid argument type';
          return result;
        }

        // Application time

        var timestamp = options.timestamp || Math.floor((hawk.utils.now() + (options.localtimeOffsetMsec || 0)) / 1000);

        // Validate credentials

        var credentials = options.credentials;
        if (!credentials ||
            !credentials.id ||
            !credentials.key ||
            !credentials.algorithm) {

          result.err = 'Invalid credential object';
          return result;
        }

        if (crypto.algorithms.indexOf(credentials.algorithm) === -1) {
          result.err = 'Unknown algorithm';
          return result;
        }

        // Parse URI

        if (typeof uri === 'string') {
          uri = hawk.utils.parseUri(uri);
        }

        // Calculate signature

        var artifacts = {
          ts: timestamp,
          nonce: options.nonce || hawk.utils.randomString(6),
          method: method,
          resource: uri.relative,
          host: uri.hostname,
          port: uri.port,
          hash: options.hash,
          ext: options.ext,
          app: options.app,
          dlg: options.dlg
        };

        result.artifacts = artifacts;

        // Calculate payload hash

        if (!artifacts.hash &&
            options.hasOwnProperty('payload')) {

          artifacts.hash = crypto.calculatePayloadHash(options.payload, credentials.algorithm, options.contentType);
        }

        var macPromise = crypto.calculateMac('header', credentials, artifacts);
        return macPromise.then( mac => {

          // Construct header

          // Other falsey values allowed
          var hasExt = artifacts.ext !== null && artifacts.ext !== undefined && artifacts.ext !== '';
          var header =
            'Hawk id="' + credentials.id +
              '", ts="' + artifacts.ts +
              '", nonce="' + artifacts.nonce +
              (artifacts.hash ? '", hash="' + artifacts.hash : '') +
              (hasExt ? '", ext="' + hawk.utils.escapeHeaderAttribute(artifacts.ext) : '') +
              '", mac="' + mac + '"';

          if (artifacts.app) {
            header += ', app="' + artifacts.app +
              (artifacts.dlg ? '", dlg="' + artifacts.dlg : '') + '"';
          }

          result.field = header;

          return result;
        });
      },

      algorithms: ['sha256'],

      calculateMac: function (type, credentials, options) {
        var normalized = hawk.utils.generateNormalizedString(type, options);
        var hc = hawkCredentials;
        return hc.doImportKey(hc.str2bin(credentials.key)).
          then(hc.doHMAC.bind(undefined, hc.str2bin(normalized))).
          then(hc.bin2base64);
      },

      calculatePayloadHash: function (payload, algorithm, contentType) {
        var dataToHash = 'hawk.' + hawk.headerVersion + '.payload\n' +
          hawk.utils.parseContentType(contentType) + '\n' + (payload || '') + '\n';
        var hc = hawkCredentials;
        return hc.doMAC(dataToHash).then(hc.bin2base64);
      }

    };


    // So as to not do twice the same work, we need to load the hawkCredentials
    // util functions. We might as well do this here.
    LazyLoader.load(['js/helpers/hawk_creds.js'], () => {
      window.hawkCredentials.then(hc => {
        hawkCredentials = hc;
        resolve(crypto);
      });
    });

  });

})(window);
