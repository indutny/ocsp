var ocsp = require('../ocsp');

var rfc3280 = require('asn1.js-rfc3280');
var rfc2560 = require('asn1.js-rfc2560');

module.exports = function check(options, cb) {
  var sync = true;
  try {
    var req = ocsp.request.generate(options.cert, options.issuer);
  } catch (e) {
    return done(e);
  }

  var exts = req.cert.tbsCertificate.extensions;
  var extnID = rfc3280['id-pe-authorityInfoAccess'].join('.');

  var infoAccess = exts.filter(function(ext) {
    return ext.extnID.join('.') === extnID;
  });

  if (infoAccess.length === 0)
    return done(new Error('AuthorityInfoAccess not found in extensions'));

  var ocspMethod = rfc2560['id-pkix-ocsp'].join('.');

  var ocspURI = null;
  var found = infoAccess.some(function(raw) {
    try {
      var ext = rfc3280.AuthorityInfoAccessSyntax.decode(raw.extnValue, 'der');
    } catch (e) {
      return false;
    }

    return ext.some(function(ad) {
      if (ad.accessMethod.join('.') !== ocspMethod)
        return false;

      var loc = ad.accessLocation;
      if (loc.type !== 'uniformResourceIdentifier')
        return false;

      ocspURI = loc.value + '';

      return true;
    });
  });

  if (!found)
    return done(new Error('id-pkix-ocsp not found in AuthorityInfoAccess'));

  sync = false;
  ocsp.utils.getResponse(ocspURI, req.data, function(err, raw) {
    if (err)
      return done(err);

    try {
      done(null, ocsp.verify({
        request: req,
        response: raw
      }));
    } catch (e) {
      return done(e);
    }
  });

  function done(err, data) {
    if (sync) {
      sync = false;
      process.nextTick(function() {
        cb(err, data);
      });
      return;
    }

    cb(err, data);
  }
};
