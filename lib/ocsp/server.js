'use strict';

var ocsp = require('../ocsp');

var http = require('http');
var util = require('util');
var crypto = require('crypto');

var async = require('async');
var rfc2560 = require('asn1.js-rfc2560');
var rfc5280 = require('asn1.js-rfc5280');

function Server(options) {
  http.Server.call(this, this.handler);

  this.options = util._extend({
    nextUpdate: 24 * 3600 * 1e3
  }, options);

  this.key = this.options.key;
  this.cert = rfc5280.Certificate.decode(
      ocsp.utils.toDER(options.cert, 'CERTIFICATE'),
      'der');
  this.cert = this.cert.tbsCertificate;

  var issuerName = rfc5280.Name.encode(this.cert.subject, 'der');
  var issuerKey = this.cert.subjectPublicKeyInfo.subjectPublicKey.data;

  this.certID = {};
  Object.keys(ocsp.utils.digestRev).forEach(function(digest) {
    this.certID[digest] = {
      issuerNameHash: crypto.createHash(digest).update(issuerName).digest(),
      issuerKeyHash: crypto.createHash(digest).update(issuerKey).digest()
    };
  }, this);

  this.certs = {};
}
util.inherits(Server, http.Server);
module.exports = Server;

Server.create = function create(options) {
  return new Server(options);
};

Server.prototype.addCert = function addCert(serial, status, info) {
  this.certs[serial.toString(16)] = {
    type: status,
    value: info
  };
};

Server.prototype.handler = function handler(req, res) {
  if (req.method !== 'POST')
    return res.writeHead(400);

  if (req.headers['content-type'] !== 'application/ocsp-request')
    return res.writeHead(400);

  var chunks = [];
  req.on('readable', function() {
    var chunk = req.read();
    if (chunk)
      chunks.push(chunk);
  });

  function errRes(status) {
    return rfc2560.OCSPResponse.encode({
      responseStatus: status
    }, 'der');
  }

  function done(out) {
    res.writeHead(200, {
      'Content-Type': 'application/ocsp-response',
      'Content-Length': out.length
    });
    res.end(out);
  }

  var self = this;
  req.on('end', function() {
    var body = Buffer.concat(chunks);
    var ocspReq;
    try {
      ocspReq = rfc2560.OCSPRequest.decode(body, 'der');
    } catch (e) {
      return done(errRes('malformed_request'));
    }

    self.getResponses(ocspReq, function(err, responses) {
      // Assume not found
      if (err) {
        res.writeHead(404);
        res.end();
        return;
      }

      return done(responses);
    });
  });

};

Server.prototype.getResponses = function getResponses(req, cb) {
  var self = this;

  var reqList = req.tbsRequest.requestList;

  // TODO(indutny): support signed requests
  async.map(reqList, function(req, cb) {
    self.getResponse(req, cb);
  }, function(err, responses) {
    if (err)
      return cb(err);

    // TODO(indutny): send extensions
    var basic = {
      tbsResponseData: {
        version: 'v1',
        responderID: {
          type: 'byKey',
          value: self.certID.sha1.issuerKeyHash
        },
        producedAt: new Date(),
        responses: responses
      },

      signatureAlgorithm: {
        algorithm: ocsp.utils.signRev.sha512WithRSAEncryption
      },
      signature: null

      // TODO(indutny): send certs?
    };

    var sign = crypto.createSign('sha512WithRSAEncryption');
    sign.update(rfc2560.ResponseData.encode(basic.tbsResponseData, 'der'));
    basic.signature = {
      unused: 0,
      data: sign.sign(self.key)
    };

    var res = {
      responseStatus: 'successful',
      responseBytes: {
        responseType: 'id-pkix-ocsp-basic',
        response: rfc2560.BasicOCSPResponse.encode(basic, 'der')
      }
    };

    cb(null, rfc2560.OCSPResponse.encode(res, 'der'));
  });
};

Server.prototype.getResponse = function getResponse(req, cb) {
  var certID = req.reqCert;

  var digestId = certID.hashAlgorithm.algorithm.join('.');
  var digest = ocsp.utils.digest[digestId];
  if (!digest)
    return cb(new Error('Unknown digest: ' + digestId));

  var expectedID = this.certID[digest];
  if (!expectedID)
    return cb(new Error('No pre-generated CertID for digest: ' + digest));

  if (expectedID.issuerNameHash.toString('hex') !==
      certID.issuerNameHash.toString('hex')) {
    return cb(new Error('Issuer name mismatch'));
  }

  if (expectedID.issuerKeyHash.toString('hex') !==
      certID.issuerKeyHash.toString('hex')) {
    return cb(new Error('Issuer key mismatch'));
  }

  var serial = certID.serialNumber.toString(16);
  var cert = this.certs[serial];

  var response = {
    certId: certID,
    certStatus: null,
    thisUpdate: new Date(),
    nextUpdate: new Date(+new Date() + this.options.nextUpdate)
  };
  if (cert) {
    response.certStatus = cert;
  } else {
    response.certStatus = {
      type: 'unknown',
      value: null
    };
  }

  cb(null, response);
};
