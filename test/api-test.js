var ocsp = require('../');
var fixtures = require('./fixtures');

var assert = require('assert');
var https = require('https');

describe('OCSP Stapling Provider', function() {
  var cert = null;
  before(function(cb) {
    var options = {
    };
    fixtures.getOCSPCert(options, function(res) {
      cert = res;
      cb();
    });
  });

  var o;
  beforeEach(function() {
    o = new ocsp.Cache();
  });

  describe('.check()', function() {
    it('should validate google.com', function(cb) {
      ocsp.check({
        cert: fixtures.google,
        issuer: fixtures.googleIssuer
      }, function(err, res) {
        if (err)
          throw err;

        assert.equal(res.type, 'good');
        cb();
      });
    });
  });

  describe('.verify()', function() {
    it('should verify reddit.com\'s stapling', function(cb) {
      var req = https.request({
        host: 'reddit.com',
        port: 443,
        requestOCSP: true
      }, function(res) {
        // Should not be called
        assert(false);
      });

      req.on('socket', function(socket) {
        socket.on('OCSPResponse', function(stapling) {
          var cert = socket.getPeerCertificate(true);

          var req = ocsp.request.generate(cert.raw, cert.issuerCertificate.raw);
          assert.doesNotThrow(function() {

            var res = ocsp.verify({
              request: req,
              response: stapling
            });

            assert.equal(res.type, 'good');
            socket.destroy();
            cb();
          });
        });
      });
    });
  });
});
