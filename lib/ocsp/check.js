var ocsp = require('../ocsp');

var crypto = require('crypto');
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
      var res = ocsp.utils.parseResponse(raw);
    } catch (e) {
      return done(e);
    }

    // Verify signature using CAs Public Key
    // TODO(indutny): support other responders
    var signAlg = ocsp.utils.sign[res.signatureAlgorithm.algorithm.join('.')];
    if (!signAlg) {
      return done(new Error('Unknown signature algorithm ' +
                            res.signatureAlgorithm.algorithm));
    }

    var verify = crypto.createVerify(signAlg);
    var tbs = res.tbsResponseData;

    var issuerKey =
        req.issuer.tbsCertificate.subjectPublicKeyInfo;
    issuerKey = ocsp.utils.toPEM(
        rfc3280.SubjectPublicKeyInfo.encode(issuerKey, 'der'), 'PUBLIC KEY');
    var signature = res.signature.data;

    verify.update(rfc2560.ResponseData.encode(tbs, 'der'));
    if (!verify.verify(issuerKey, signature))
      return done(new Error('Invalid signature'));

    if (tbs.responses.length < 1)
      return done(new Error('Expected at least one response'));

    var res = tbs.responses[0];

    // Verify CertID
    // XXX(indutny): verify parameters
    if (res.certId.hashAlgorithm.algorithm.join('.') !==
        req.certID.hashAlgorithm.algorithm.join('.')) {
      return done(new Error('Hash algorithm mismatch'));
    }

    if (res.certId.issuerNameHash.toString('hex') !==
        req.certID.issuerNameHash.toString('hex')) {
      return done(new Error('Issuer name hash mismatch'));
    }

    if (res.certId.issuerKeyHash.toString('hex') !==
        req.certID.issuerKeyHash.toString('hex')) {
      return done(new Error('Issuer key hash mismatch'));
    }

    if (res.certId.serialNumber.cmp(req.certID.serialNumber) !== 0)
      return done(new Error('Serial number mismatch'));

    if (res.certStatus.type !== 'good') {
      return done(new Error('OCSP Status: ' + res.certStatus.type),
                  res.certStatus);
    }

    var now = +new Date;
    var nudge = options.nudge || 60000;
    if (res.thisUpdate + nudge > now || res.nextUpdate - nudge < now)
      return done(new Error('OCSP Response expired'));

    done(null, res.certStatus);
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
