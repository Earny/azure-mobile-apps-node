// ----------------------------------------------------------------------------
// Copyright (c) Microsoft Corporation. All rights reserved.
// ----------------------------------------------------------------------------
var https = require('https'),
    url = require('url'),
    jwt = require('@earny/jsonwebtoken'),
    promises = require('../utilities/promises'),
    log = require('../logger'),
    normalizeClaims = require('./normalizeClaims');

module.exports = function (authConfiguration, token, provider) {
    var decodedToken;
    try {
      decodedToken = jwt.decode(token);
    } catch (err) {
    }

    var endpoint = url.parse(decodedToken.iss || authConfiguration.issuer);

    return promises.create(function (resolve, reject) {
        var requestOptions = {
            hostname: endpoint.hostname,
            port: endpoint.port || 443,
            path: '/.auth/me' + (provider ? '?provider=' + provider : ''),
            method: 'GET',
            headers: {
                'x-zumo-auth': token
            }
        };
        log.silly('GetIdentity Request: ', requestOptions);
        
        var request = https.request(requestOptions, function (response) {
           log.silly('GetIdentity Response Code: ', response.statusCode);
           
           var responseData = '';
           response.setEncoding('utf8');
           response.on('data', function (chunk) {
               responseData += chunk;
           });
           response.on('end', function () {
               log.silly('GetIdentity Response: ', responseData);
               try {
                 var responseObj = normalizeClaims(JSON.parse(responseData));
                 resolve(responseObj);
               } catch (err) {
                 console.error('@@@ DEBUG @@@: cannot parse response', endpoint, endpoint.hostname, endpoint.port, responseData);
                 reject(err);
               }
           });
        });
        
        request.on('error', function (error) {
            log.silly('Could not retrieve identity: ', error);
            reject(error);
        });
        
        request.end();
    });
};
