var ocsp = require('../');
var fixtures = require('./fixtures');

var assert = require('assert');
var https = require('https');

describe('OCSP Agent', function() {
  var a;
  beforeEach(function() {
    a = new ocsp.Agent();
  });

  it('should connect and validate google.com', function(cb) {
    var req = https.get({
      host: 'www.google.com',
      port: 443,
      agent: a
    }, function(res) {
      res.resume();
      cb();
    });
  });
});
