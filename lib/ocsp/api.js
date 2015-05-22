var ocsp = require('../ocsp');
var rfc2560 = require('asn1.js-rfc2560');
var rfc3280 = require('asn1.js-rfc3280');

exports.getOCSPURI = function getOCSPURI(rawCert, cb) {
  var ocspMethod = rfc2560['id-pkix-ocsp'].join('.');

  var cert = ocsp.utils.toDER(rawCert, 'CERTIFICATE');
  cert = rfc3280.Certificate.decode(cert, 'der');

  ocsp.utils.getAuthorityInfo(cert, ocspMethod, cb);
};
