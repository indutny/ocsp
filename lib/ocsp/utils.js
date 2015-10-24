'use strict';

var http = require('http');
var util = require('util');
var url = require('url');
var asn1 = require('asn1.js');

var rfc2560 = require('asn1.js-rfc2560');
var rfc3280 = require('asn1.js-rfc3280');

exports['id-ad-caIssuers'] = [ 1, 3, 6, 1, 5, 5, 7, 48, 2 ];

exports.getResponse = function getResponse(uri, req, cb) {
  uri = url.parse(uri);

  var options = util._extend({
    method: 'POST',
    headers: {
      'Content-Type': 'application/ocsp-request',
      'Content-Length': req.length
    }
  }, uri);

  function done(err, response) {
    if (cb)
      cb(err, response);
    cb = null;
  }

  function onResponse(response) {
    if (response.statusCode < 200 || response.statusCode >= 400) {
      return done(
        new Error('Failed to obtain OCSP response: ' + response.statusCode));
    }

    var chunks = [];
    response.on('readable', function() {
      var chunk = response.read();
      if (!chunk)
        return;
      chunks.push(chunk);
    });
    response.on('end', function() {
      var ocsp = Buffer.concat(chunks);

      done(null, ocsp);
    });
  }

  http.request(options, onResponse)
      .on('error', done)
      .end(req);
};

exports.parseResponse = function parseResponse(raw) {
  var response = rfc2560.OCSPResponse.decode(raw, 'der');

  var status = response.responseStatus;
  if (status !== 'successful')
    throw new Error('Bad OCSP response status: ' + status);

  // Unknown response type
  var responseType = response.responseBytes.responseType;
  if (responseType !== 'id-pkix-ocsp-basic')
    throw new Error('Unknown OCSP response type: ' + responseType);

  var bytes = response.responseBytes.response;
  var basic = rfc2560.BasicOCSPResponse.decode(bytes, 'der');

  return basic;
};

exports.digest = {
  '1.3.14.3.2.26': 'sha1',
  '2.16.840.1.101.3.4.2.1': 'sha256'
};

exports.digestRev = {
  sha1: '1.3.14.3.2.26',
  sha256: '2.16.840.1.101.3.4.2.1'
};

exports.sign = {
  '1.2.840.113549.1.1.5': 'sha1WithRSAEncryption',
  '1.2.840.113549.1.1.11': 'sha256WithRSAEncryption',
  '1.2.840.113549.1.1.12': 'sha384WithRSAEncryption',
  '1.2.840.113549.1.1.13': 'sha512WithRSAEncryption'
};

exports.signRev = {
  sha1WithRSAEncryption: [ 1, 2, 840, 113549, 1, 1, 5 ],
  sha256WithRSAEncryption: [ 1, 2, 840, 113549, 1, 1, 11 ],
  sha384WithRSAEncryption: [ 1, 2, 840, 113549, 1, 1, 12 ],
  sha512WithRSAEncryption: [ 1, 2, 840, 113549, 1, 1, 13 ]
};

exports.toPEM = function toPEM(buf, label) {
  var p = buf.toString('base64');
  var out = [ '-----BEGIN ' + label + '-----' ];
  for (var i = 0; i < p.length; i += 64)
    out.push(p.slice(i, i + 64));
  out.push('-----END ' + label + '-----');
  return out.join('\n');
};

exports.toDER = function toDER(raw, what) {
  var der = raw.toString().match(new RegExp(
      '-----BEGIN ' + what + '-----([^-]*)-----END ' + what + '-----'));
  if (der)
    der = new Buffer(der[1].replace(/[\r\n]/g, ''), 'base64');
  else if (typeof raw === 'string')
    der = new Buffer(raw);
  else
    der = raw;
  return der;
};

exports.getAuthorityInfo = function getAuthorityInfo(cert, key, done) {
  var exts = cert.tbsCertificate.extensions;
  if (!exts)
    exts = [];
  var extnID = rfc3280['id-pe-authorityInfoAccess'].join('.');

  var infoAccess = exts.filter(function(ext) {
    return ext.extnID.join('.') === extnID;
  });

  if (infoAccess.length === 0)
    return done(new Error('AuthorityInfoAccess not found in extensions'));

  var res = null;
  var found = infoAccess.some(function(raw) {
    var ext;
    try {
      ext = rfc3280.AuthorityInfoAccessSyntax.decode(raw.extnValue, 'der');
    } catch (e) {
      return false;
    }

    return ext.some(function(ad) {
      if (ad.accessMethod.join('.') !== key)
        return false;

      var loc = ad.accessLocation;
      if (loc.type !== 'uniformResourceIdentifier')
        return false;

      res = loc.value + '';

      return true;
    });
  });

  if (!found)
    return done(new Error(key + ' not found in AuthorityInfoAccess'));

  return done(null, res);
};

var RSAPrivateKey = asn1.define('RSAPrivateKey', function() {
  this.seq().obj(
    this.key('version').int(),
    this.key('modulus').int(),
    this.key('publicExponent').int(),
    this.key('privateExponent').int(),
    this.key('prime1').int(),
    this.key('prime2').int(),
    this.key('exponent1').int(),
    this.key('exponent2').int(),
    this.key('coefficient').int()
  );
});
exports.RSAPrivateKey = RSAPrivateKey;
