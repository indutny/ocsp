var ocsp = require('../');
var fixtures = require('./fixtures');

var assert = require('assert');
var https = require('https');

describe('OCSP Agent', function() {
  var a;
  beforeEach(function() {
    a = new ocsp.Agent();
  });

  var websites = [
    'www.google.com',
    'google.com',
    'helloworld.letsencrypt.org',
    'yahoo.com',
    'nytimes.com',
    'microsoft.com'
  ];

  websites.forEach(function(host) {
    it('should connect and validate ' + host, function(cb) {
      var req = https.get({
        host: host,
        port: 443,
        agent: a
      }, function(res) {
        res.resume();
        cb();
      });
    });
  });
});
