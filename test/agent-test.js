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

  it('should connect and validate letsencrypt.org', function(cb) {
    var req = https.get({
      host: 'helloworld.letsencrypt.org',
      port: 443,
      agent: a
    }, function(res) {
      res.resume();
      cb();
    });
  });
});
