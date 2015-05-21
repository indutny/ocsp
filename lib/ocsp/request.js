var crypto = require('crypto');
var rfc2560 = require('asn1.js-rfc2560');
var rfc3280 = require('asn1.js-rfc3280');
var Buffer = require('buffer').Buffer;

function sha1(data) {
  return crypto.createHash('sha1').update(data).digest();
}

function toDER(raw) {
  var der = raw.toString().match(
      /-----BEGIN CERTIFICATE-----([^-]*)-----END CERTIFICATE-----/);
  if (der)
    der = new Buffer(der[1].replace(/[\r\n]/g, ''), 'base64');
  else if (typeof raw === 'string')
    der = new Buffer(raw);
  else
    der = raw;
  return der;
}

exports.generate = function generate(rawCert, rawIssuer) {
  var cert = rfc3280.Certificate.decode(toDER(rawCert), 'der');
  var issuer = rfc3280.Certificate.decode(toDER(rawIssuer), 'der');
  var tbsCert = cert.tbsCertificate;
  var tbsIssuer = issuer.tbsCertificate;

  var certID = {
    hashAlgorithm: {
      // algorithm: [ 2, 16, 840, 1, 101, 3, 4, 2, 1 ]  // sha256
      algorithm: [ 1, 3, 14, 3, 2, 26 ]  // sha1
    },
    issuerNameHash: sha1(rfc3280.Name.encode(tbsCert.issuer, 'der')),
    issuerKeyHash: sha1(
      tbsIssuer.subjectPublicKeyInfo.subjectPublicKey.data),
      serialNumber: tbsCert.serialNumber
  };

  var tbs = {
    version: 'v1',
    requestList: [ {
      reqCert: certID
    } ],
    requestExtensions: [ {
      extnID: rfc2560['id-pkix-ocsp-nonce'],
      critical: false,
      extnValue: rfc2560.Nonce.encode(crypto.randomBytes(16), 'der')
    } ]
  };

  var req = {
    tbsRequest: tbs
  };

  return {
    id: sha1(rfc2560.CertID.encode(certID, 'der')),
    data: rfc2560.OCSPRequest.encode(req, 'der'),

    // Just to avoid re-parsing DER
    cert: cert,
    issuer: issuer
  };
};
