var ocsp = require('../');
var fixtures = require('./fixtures');

var assert = require('assert');
var https = require('https');

describe('OCSP Server', function() {
  var issuer = { cert: null, key: null };
  var good = { cert: null, key: null };
  var revoked = { cert: null, key: null };

  before(function(cb) {
    var options = {
      serial: 42,
      commonName: 'mega.ca',
      size: 1024
    };
    fixtures.getOCSPCert(options, function(cert, key) {
      issuer.cert = cert;
      issuer.key = key;

      var options = {
        issuer: cert,
        issuerKey: key,
        serial: 43
      };

      fixtures.getOCSPCert(options, function(cert, key) {
        good.cert = cert;
        good.key = key;

        options.serial++;
        fixtures.getOCSPCert(options, function(cert, key) {
          revoked.cert = cert;
          revoked.key = key;
          cb();
        });
      });
    });
  });

  it('should provide ocsp response to the client', function(cb) {
    var server = ocsp.Server.create({
      cert: issuer.cert,
      key: issuer.key
    });

    server.addCert(43, 'good');
    server.addCert(44, 'revoked', {
      revocationTime: new Date(),
      revocationReason: 'CACompromise'
    });

    server.listen(8000, function() {
      ocsp.check({
        cert: good.cert,
        issuer: issuer.cert
      }, function(err, res) {
        if (err)
          throw err;

        assert.equal(res.type, 'good');

        next();
      });
    });

    function next() {
      ocsp.check({
        cert: revoked.cert,
        issuer: issuer.cert
      }, function(err, res) {
        assert(err);
        assert.equal(res.type, 'revoked');
        cb();
      });
    }
  });
});
