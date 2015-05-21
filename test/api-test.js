var ocsp = require('../');
var fixtures = require('./fixtures');

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

  it('should validate google.com', function(cb) {
    ocsp.check(fixtures.google, fixtures.googleIssuer, function(err, res) {
      if (err)
        throw err;

      console.log(res);

      cb();
    });
  });
});
