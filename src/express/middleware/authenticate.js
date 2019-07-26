// ----------------------------------------------------------------------------
// Copyright (c) Microsoft Corporation. All rights reserved.
// ----------------------------------------------------------------------------
/**
@module azure-mobile-apps/src/express/middleware/authenticate
@description Validates JWT tokens provided in an HTTP request header called
x-zumo-auth. If tokens are valid, a {@link module:azure-mobile-apps/src/auth/user user object}
is attached to the request.azureMobile property. If tokens are invalid, a HTTP
status of 401 is returned to the client.
*/
var auth = require('../../auth');
var debug = require('debug')('@earny/azure-mobile-apps:express:authenticate');

/**
Create a new instance of the authenticate middleware
@param {configuration} configuration The mobile app configuration
@example
<caption>Using the authenticate middleware in a custom express route</caption>
// you must pass in the mobile app configuration so the auth middleware can access auth configuration (secret, issuer, etc)
module.exports = function (configuration) {}
    var router = require('express').Router(),
        authenticate = require('azure-mobile-apps/src/express/middleware/authenticate')(configuration);

    router.get('/', function (req, res, next) {
        res.status(200).send("GET executed");
    });

    router.post('/add', authenticate, function (req, res, next) {
        res.status(200).send("POST executed - you are logged in as " + req.azureMobile.user.id);
    });
};
*/
module.exports = function(configuration) {
    if (configuration && configuration.auth && Object.keys(configuration.auth).length > 0) {
        var authUtils = auth(configuration.auth);

        return function(req, res, next) {
            debug('Authenticate request')
            // If the X-ZUMO-AUTH header is there, use that.  If the X-ZUMO-AUTH
            // header is not there, then look for a Bearer Authorization header.
            var token = req.get('x-zumo-auth') || req.get('authorization');

            if (token) {
                // Check to see if the token has the bearer in the front - Authorization
                // will, X-ZUMO-AUTH won't.  Remove it if present
                if (token.toLowerCase().substr(0, 7) === 'bearer ') {
                    token = token.substr(7);
                }

                req.azureMobile = req.azureMobile || {};
                req.azureMobile.auth = authUtils;

                debug('Validate token '+(token || '').substring(0, 5));

                if (configuration.auth.validateTokens !== false) {
                    debug('Will validate token');
                    authUtils.validate(token)
                        .then(function(user) {
                            debug('Token validated!');
                            req.azureMobile.user = user;
                            next();
                        })
                        .catch(function(error) {
                            debug('Token is invalid');
                            res.status(401).send(error);
                        });
                } else {
                    try {
                        req.azureMobile.user = authUtils.decode(token);
                        next();
                    } catch (error) {
                        res.status(401).send(error);
                    }
                }
            } else {
                next();
            }
        };
    } else {
        return function(req, res, next) {
            next();
        };
    }
};