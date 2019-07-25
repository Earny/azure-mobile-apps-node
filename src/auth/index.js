// ----------------------------------------------------------------------------
// Copyright (c) Microsoft Corporation. All rights reserved.
// ----------------------------------------------------------------------------
/**
@module azure-mobile-apps/src/auth
@description Helper functions for working with JWT tokens
*/
var user = require('./user'),
    jwt = require('@earny/jsonwebtoken'),
    promises = require('../utilities/promises'),
    got = require('got');

function parseBase64(str) {
    try {
        return JSON.parse(Buffer.from(str, 'base64').toString('utf-8'));
    } catch(e) {
        return null;
    }
}

function isV2Token(token){
    try {
        if(typeof token === 'string') {
            var parts = token.split('.');
            if(parts.length <= 0) {
                return false;
            }

            var headerObj = parseBase64(parts[0]);
            var bodyObj = parseBase64(parts[1]);

            if(headerObj && headerObj.kid != null){
                if(bodyObj && bodyObj.iss && bodyObj.iss.indexOf('pharaoh') !== -1) {
                    return bodyObj;
                }
            }
        }
        return false;
    } catch (e) {
        console.error('error checking v2 token', e);
        return false;
    }
}

function v2User(configuration, token, data) {
    return user({
          ...(configuration || {}),
          getIdentity: () => { throw new Error('Cannot get identity of v2 user through this method'); }
      },
      token,
      data
    )
}

function validateV2Token(endpoint, apikey, authConfig, token) {
    if(!endpoint) {
        return promises.rejected(new Error('Invalid v2 endpoint configured: ' + endpoint));
    }

    var v2Token = isV2Token(token);
    if(apikey && v2Token) {
        return promises.create(function(resolve, reject) {
            got(endpoint, {
                body: JSON.stringify({
                    'v2token': token,
                }),
                method: 'POST',
                headers: {
                    'Authorization': apikey,
                    'Content-Type': 'application/json',
                }
            })
              .then((a) => {
                  console.log('success', a);
                  return resolve(v2User(authConfig, token, v2Token))
              })
              .catch((err) => reject(err));
        });
    }

    if(apikey == null || apikey.length === 0) {
        return promises.rejected(new Error('Bad API key for v2 auth'));
    }

    return promises.rejected(new Error('Invalid token'));
}

/**
Create an instance of a helper based on the supplied configuration.
@param {authConfiguration} configuration The authentication configuration
@returns An object with members described below.
*/
module.exports = function (configuration) {
    var key = configuration.azureSigningKey ? hexStringToBuffer(configuration.azureSigningKey) : configuration.secret;
    var v2VerifyEndpoint = configuration.v2VerifyEndpoint || null;
    var v2ApiKey = configuration.v2VerifyApiKey || null;
    var v2Enabled = configuration.v2VerifyEnabled || false;

    return {
        /**
        Validate a JWT token
        @param {string|Buffer} token The JWT token to validate
        @returns A promise that yields a {@link module:azure-mobile-apps/src/auth/user user} object on success.
        @example
var auth = require('azure-mobile-apps/src/auth')(mobileApp.configuration.auth);
if(auth.validate(req.get('x-zumo-auth')))
    res.status(200).send("Successfully authenticated");
else
    res.status(401).send("You must be logged in");
        */
        validate: function (token) {

            //Feature flag to ensure nothing new is executed unless explicitly enabled
            if(v2Enabled === true) {
                return validateV2Token(v2VerifyEndpoint, v2ApiKey, configuration, token);
            }

            return promises.create(function (resolve, reject) {
                var options = {
                    audience: configuration.audience || 'urn:microsoft:windows-azure:zumo',
                    issuer: configuration.issuer || 'urn:microsoft:windows-azure:zumo'
                };

                jwt.verify(token, key, options, function (err, claims) {
                    if(err)
                        reject(err);
                    else {
                        resolve(user(configuration, token, claims));
                    }
                });
            });
        },
        /**
        Decode a JWT token without validating
        @param {string} token The payload to sign
        @returns {module:azure-mobile-apps/src/auth/user} A user object for the token
        */
        decode: function (token) {
            return user(configuration, token, jwt.decode(token));
        },
        /**
        Create a token from the specified payload
        @param {object} payload The payload to sign
        @returns {string} The signed token.
        @example
var auth = require('azure-mobile-apps/src/auth')(mobileApp.configuration.auth);
res.status(200).send(auth.sign({ sub: "myUserId" }));
        */
        sign: function (payload) {
            var options = { };

            if(!payload.aud)
                options.audience = configuration.audience || 'urn:microsoft:windows-azure:zumo';

            if(!payload.iss)
                options.issuer = configuration.issuer || 'urn:microsoft:windows-azure:zumo';

            if(!payload.exp)
                options.expiresIn = (configuration.expires || 1440) * 60;

            return jwt.sign(payload, key, options);
        }
    };
};

function hexStringToBuffer(hexString) {
    var bytes = [];
    for (var i = 0; i < hexString.length; i += 2)
        bytes.push(parseInt(hexString.substr(i, 2), 16));
    return new Buffer.from(bytes);
}
