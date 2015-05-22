var ocsp = require('../ocsp');
var rfc2560 = require('asn1.js-rfc2560');
var rfc3280 = require('asn1.js-rfc3280');
var crypto = require('crypto');

module.exports = function verify(options, cb) {
  var req = options.request;

  try {
    var issuer = req.issuer ||
                 rfc3280.Certificate.decode(
                     ocsp.utils.toDER(options.issuer, 'CERTIFICATE'),
                     'der');

    var res = ocsp.utils.parseResponse(options.response);
  } catch (e) {
    return done(e);
  }

  // Verify signature using CAs Public Key
  // TODO(indutny): support other responders
  var signAlg = ocsp.utils.sign[res.signatureAlgorithm.algorithm.join('.')];
  if (!signAlg) {
    done(new Error('Unknown signature algorithm ' +
                   res.signatureAlgorithm.algorithm));
    return;
  }

  var verify = crypto.createVerify(signAlg);
  var tbs = res.tbsResponseData;

  var issuerKey = issuer.tbsCertificate.subjectPublicKeyInfo;
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
    return done(new Error('OCSP Status: ' + res.certStatus.type));
  }

  var now = +new Date;
  var nudge = options.nudge || 60000;
  if (res.thisUpdate - nudge > now || res.nextUpdate + nudge < now)
    return done(new Error('OCSP Response expired'));

  return done(null);

  function done(err) {
    process.nextTick(function() {
      cb(err, res && res.certStatus);
    });
  }
};
