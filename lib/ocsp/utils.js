var http = require('http');
var url = require('url');
var rfc2560 = require('asn1.js-rfc2560');

exports.getResponse = function getResponse(uri, req, cb) {
  uri = url.parse(uri);

  var options = {
    method: 'POST',
    host: uri.host,
    path: uri.path,
    headers: {
      'Content-Type': 'application/ocsp-request',
      'Content-Length': req.length
    }
  };

  http.request(options, onResponse)
      .on('error', done)
      .end(req);

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

  function done(err, response) {
    if (cb)
      cb(err, response);
    cb = null;
  }
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
