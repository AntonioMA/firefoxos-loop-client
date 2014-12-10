module.exports = function(grunt) {

  grunt.registerTask('configureProduction', function() {
    grunt.option("loopServer", "production");
    grunt.option("metrics", "production");
    grunt.option("debug", false);
    grunt.option("enforceDevices", true);
    grunt.option("performanceLog", "false");
  });

  grunt.registerTask('configureDevelopment', function() {
    grunt.option("loopServer", "development");
    grunt.option("metrics", "stage");
    grunt.option("debug", true);
    grunt.option("enforceDevices", false);
    grunt.option("performanceLog", "persistent");
  });

  grunt.registerTask('configure', function() {
    // Device Compatibilty Configuration, when enabled, only
    // the ALCATELOneTouch6015X is allowed
    var enforceDevices = grunt.option('enforceDevices') || false;
    if (enforceDevices) {
      var compatibilityF = "build/compatibility.json";
      var compatibility = grunt.file.readJSON(compatibilityF);
      compatibility.device.names = ["ALCATELOneTouch6015X"];
      grunt.file.write(compatibilityF, JSON.stringify(compatibility, null, 2));
    }

    // Read manifest and config files and some configuration operations require
    // changes in both of them
    var manifestFile = "build/manifest.webapp";
    var manifest = grunt.file.readJSON(manifestFile); //get file as a string

    var configFile = "build/js/config.js";
    var config = grunt.file.readJSON(configFile); //get file as a json

    // Configure debug parameter, just require changes in config.js
    var debug = grunt.option('debug') || false;
    var DEBUG_DEF_VAL = false;
    if (debug) {
      config.debug = true;
    } else {
      config.debug = false;
    }

    // Configure loop version, require changes in config.js for telemetry report
    // and manifest.webapp for marketplace
    var version = grunt.option('loopVersion');
    var VERSION_DEF_VAL = "1.1d";
    if (version != undefined) {
      config.version = version;
      manifest.version = version;
    }

    // Configure loop server, require changes in config.js for server config
    // and manifest.webapp for app origin
    var loopServer = grunt.option('loopServer') || "production";
    var SERVER_DEF_VAL = "server_url: 'https://loop.services.mozilla.com'";
    var appOrigin = "loop.services.mozilla.com";
    var port = "";
    var protocol = "https";
    switch (loopServer) {
      case "stage":
        appOrigin = "loop.stage.mozaws.net";
        manifest.name = "Hello Stage";
        var locales = manifest.locales;
        for (var i in locales) {
          locales[i].name = "Hello Stage";
        }
        break;
      case "development":
        appOrigin = "loop-dev.stage.mozaws.net";
        manifest.name = "Hello Dev";
        var locales = manifest.locales;
        for (var i in locales) {
          locales[i].name = "Hello Dev";
        }
        break;
      case "production":
        appOrigin = "loop.services.mozilla.com";
        break;
      default:
        // Check if the configuration parameter includes a valid URL, if so,
        // we will configure it as the loop server, otherwise, fallback to 
        // default
        var url = require('url');
        var serverUrl = url.parse(loopServer);
        if (serverUrl.hostname != null) {
          appOrigin = serverUrl.hostname;
          manifest.name = "Hello " + hostname;
          var locales = manifest.locales;
          for (var i in locales) {
            locales[i].name = "Hello " + hostname;
          }
          if (serverUrl.port != null) {
            port = ":" + serverUrl.port;
          }
          if (serverUrl.protocol == "http:") {
            config.allowUnsecure = true;
            protocol = "http";
          }
        }
        break;
    }
    config.server_url = protocol + "://" + appOrigin + port;
    manifest.origin = "app://" + appOrigin;
    grunt.config.set("origin", appOrigin);

    // Configure performance logs, require changes in config.js
    var performanceLog = grunt.option('performanceLog') || "disabled";
    switch (performanceLog) {
      case "persistent":
        config.performanceLog.enabled = true;
        config.performanceLog.persistent = true;
        break;
      case "enabled":
        config.performanceLog.enabled = true;
        config.performanceLog.persistent = false;
        break;
      case "disabled":
      default:
        config.performanceLog.enabled = false;
        config.performanceLog.persistent = false;
        break;
    }

    // Configure metrics (telemetry and input.mozilla), changes only config.js
    var metrics = grunt.option('metrics') || "stage";
    switch (metrics) {
      case "production":
        config.metrics.enabled = true;
        config.metrics.feedback.serverUrl = 'https://input.mozilla.org/api/v1/feedback';
        config.metrics.telemetry.serverUrl = 'https://fxos.telemetry.mozilla.org/submit/telemetry';
        break;
      case "stage":
        config.metrics.enabled = true;
        config.metrics.feedback.serverUrl = 'https://input.allizom.org/api/v1/feedback';
        config.metrics.telemetry.serverUrl = 'https://fxos.telemetry.mozilla.org/submit/telemetry';
        break;
      case "disabled":
      default:
        config.metrics.enabled = false;
        config.metrics.feedback.serverUrl = 'https://input.allizom.org/api/v1/feedback';
        config.metrics.telemetry.serverUrl = 'https://fxos.telemetry.mozilla.org/submit/telemetry';
        break;
    }

    grunt.file.write(configFile, JSON.stringify(config, null, 2));
    grunt.file.write(manifestFile, JSON.stringify(manifest, null, 2));
  });
}

