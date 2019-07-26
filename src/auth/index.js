// ----------------------------------------------------------------------------
// Copyright (c) Microsoft Corporation. All rights reserved.
// ----------------------------------------------------------------------------
/**
@module azure-mobile-apps/src/auth
@description Helper functions for working with JWT tokens
*/
var user = require('./user'),
    debug = require('debug')('@earny/azure-mobile-apps:auth:validate'),
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
        debug('Checking if token '+(token || '').substring(0,5)+' is v2 token');
        if(typeof token === 'string') {
            var parts = token.split('.');
            if(parts.length <= 0) {
                debug('Is not v2 token, too short: '+parts.length+' segments instead of 2+');
                return false;
            }

            var headerObj = parseBase64(parts[0]);
            var bodyObj = parseBase64(parts[1]);

            if(headerObj && headerObj.kid != null){
                if(bodyObj && bodyObj.iss && bodyObj.iss.toLowerCase().indexOf('pharaoh') !== -1) {
                    return bodyObj;
                }
                debug('Token was not issued by pharaoh');
            }
        }
        debug('Is not v2 token');
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
        debug('Invalid v2 endpoint, not v2 token');
        return promises.rejected(new Error('Invalid v2 endpoint configured: ' + endpoint));
    }

    if(apikey == null || apikey.length === 0) {
        return promises.rejected(new Error('Bad API key for v2 auth'));
    }

    var v2Token = isV2Token(token);
    if(apikey && v2Token) {
        debug('Validate against v2 endpoint');
        return promises.create(function(resolve, reject) {
            debug('Executing request');
            got(endpoint, {
                body: {
                    'v2token': token,
                },
                method: 'POST',
                headers: {
                    'Authorization': apikey,
                    'Content-Type': 'application/json',
                },
                json: true,
            })
              .then((res) => {
                  try {
                      var valid = typeof res.body === 'string' ? JSON.parse(res.body).valid : res.body.valid;
                      debug('Got response ('+valid+') from v2 verify endpoint');
                      if (valid && valid.toLowerCase() === 'ok') {
                          debug('Is valid v2 token');
                          return resolve(v2User(authConfig, token, v2Token));
                      }
                      debug('Invalid v2 token');
                  } catch(e) {
                      debug('Error was thrown, potentially invalid token: '+e);
                      return void reject(new Error('Failed to validate'));
                  }

                  throw new Error('Forbidden');
              })
              .catch((err) => {
                  if(err.statusCode === 403)
                    return void reject(new Error('Forbidden'));

                  console.error(err);
                  return void reject(new Error('Internal Error'));
              });
        });
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
    /**
     * Pharaoh Integration @TODO Try to make this load from be-mobile if you dare
     */
    var v2VerifyEndpoint = process.env.BACKEND_MOBILE_V2_VERIFY_ENDPOINT || null;
    var v2ApiKey = process.env.BACKEND_MOBILE_V2_APIKEY || null;
    var v2Enabled = process.env.BACKEND_MOBILE_V2_VERIFY_ENABLED_FLAG === 'true';

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
            debug('Validate token'+(token || '').substring(0, 5));
            debug('V2 Info: Enabled='+v2Enabled+', endpoint='+v2VerifyEndpoint);

            //Feature flag to ensure nothing new is executed unless explicitly enabled
            if(v2Enabled === true) {
                debug('Validating against v2 system');
                return validateV2Token(v2VerifyEndpoint, v2ApiKey, configuration, token);
            }

            debug('Validating against v1');
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
    return new Buffer(bytes);
}
