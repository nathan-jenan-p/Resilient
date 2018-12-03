'use strict';

let request = require('request');
let _ = require('lodash');
let util = require('util');
let net = require('net');
let config = require('./config/config');
let async = require('async');
let fs = require('fs');
let Logger;
let requestWithDefaults;
let previousDomainRegexAsString = '';
let domainBlacklistRegex = null;



function startup(logger) {
    Logger = logger;
    let defaults = {};

    if (typeof config.request.cert === 'string' && config.request.cert.length > 0) {
        defaults.cert = fs.readFileSync(config.request.cert);
    }

    if (typeof config.request.key === 'string' && config.request.key.length > 0) {
        defaults.key = fs.readFileSync(config.request.key);
    }

    if (typeof config.request.passphrase === 'string' && config.request.passphrase.length > 0) {
        defaults.passphrase = config.request.passphrase;
    }

    if (typeof config.request.ca === 'string' && config.request.ca.length > 0) {
        defaults.ca = fs.readFileSync(config.request.ca);
    }

    if (typeof config.request.proxy === 'string' && config.request.proxy.length > 0) {
        defaults.proxy = config.request.proxy;
    }

    if (typeof config.request.rejectUnauthorized === 'boolean') {
        defaults.rejectUnauthorized = config.request.rejectUnauthorized;
    }

    let defaultRequest = request.defaults(defaults);
    requestWithDefaults = (options, requestOptions, cb) => {
        defaultRequest(requestOptions, (err, resp, data) => {
            if (err) {
                cb(err, resp, data);
                return;
            }

            if (resp.statusCode === 401) {
                deleteToken(options);
                createToken(options, (err, token) => {
                    if (err) {
                        cb(err);
                        return;
                    }

                    requestOptions.headers = { 'X-sess-id': token.token, 'Cookie': token.cookies };

                    defaultRequest(requestOptions, cb);
                });
                return;
            }

            cb(err, resp, data);
        });
    }
}

let tokens = {};

/**
 *
 * @param entities
 * @param options
 * @param cb
 */

function getTokenFromCache(options) {
    return tokens[options.username + options.password];
}

function setTokenInCache(options, token) {
    tokens[options.username + options.password] = token;
}

function deleteToken(options) {
    delete tokens[options.username + options.password];
}


var createToken = function (options, cb) {
    let token = getTokenFromCache(options);
    if (token) {
        token.counter++;
        cb(null, token);
    } else {
        let requestOptions = {
            uri: options.url + '/rest/session',
            method: 'POST',
            body: {
                "email": options.username,
                "password": options.password,
                "interactive": true
            },
            json: true
        };

        Logger.trace({ request: requestOptions }, "Checking the request options for auth token");

        requestWithDefaults(options, requestOptions, function (err, response, body) {
            let errorObject = _isApiError(err, response, body);
            Logger.trace({ error: errorObject }, "Checking to see if there is an error in request");
            if (errorObject) {
                cb(errorObject);
                return;
            }

            let csrfToken = body.csrf_token;

            let token = {
                token: csrfToken,
                cookies: response.headers['set-cookie'],
                counter: 1
            };

            setTokenInCache(options, token);

            cb(null, token);
        });
    }
};

function doLookup(entities, options, cb) {

    Logger.debug({ options: options }, 'Options');
    let lookupResults = [];

    createToken(options, function (err, token) {
        if (err) {
            cb({
                detail: "Error Creating Session",
                err: err
            });
            destroyToken(options, token);
            return;
        } else {
            async.each(entities, function (entityObj, next) {
                if (entityObj.value !== null) {
                    _lookupEntity(entityObj, options, token, function (err, result) {
                        if (err) {
                            next(err);
                        } else {
                            Logger.debug({ results: result }, "Logging results");
                            lookupResults.push(result);
                            next(null);
                        }
                    });
                } else {
                    lookupResults.push({ entity: entityObj, data: null }); //Cache the missed results
                    next(null);
                }
            }, function (err) {
                destroyToken(options, token);
                // Logger.debug({ lookup: lookupResults }, "Checking to see if the results are making its way to lookupresults");
                cb(err, lookupResults);
            });
        }
    });
}


function _lookupEntity(entityObj, options, token, cb) {
    let lookupResults = [];
    let host = options.url

    let requestOptions = {
        uri: options.url + '/rest/search_ex',
        method: 'POST',
        headers: { 'X-sess-id': token.token, 'Cookie': token.cookies },
        body: {
            "org_id": 220,
            "query": entityObj.value,
            "min_required_results": 0,
            "types": [
                "incident"
            ]
        },
        json: true
    };

    Logger.trace({ data: requestOptions }, "Logging requestOptions");

    requestWithDefaults(options, requestOptions, function (err, response, body) {
        let errorObject = _isApiError(err, response, body, entityObj.value);
        // Logger.trace({ error: errorObject }, "Checking to see if there is an error in lookEntity request");
        if (errorObject || (response && response.statusCode !== 200)) {
            cb({ err: errorObject, statusCode: response ? response.statusCode : "unknown" });
            return;
        }

        Logger.trace({ resonse: response }, "Checking the reponse of the query");
        Logger.trace({ data: body }, "Logging Body Data of the sha256");

        if (!body || !body.results || body.results.length === 0) {
            cb(null, {
                entity: entityObj,
                data: null
            });
            return;
        }

        if (_isLookupMiss(response)) {
            cb(null, {
                entity: entityObj,
                data: null
            });
            return;
        }

        let incidents = [];

        body.results.forEach(function (data) {
            incidents.push(data.obj_id);
        });

        // The lookup results returned is an array of lookup objects with the following format
        cb(null, {
            // Required: This is the entity object passed into the integration doLookup method
            entity: entityObj,
            // Required: An object containing everything you want passed to the template
            data: {
                // We are constructing the tags using a custom summary block so no data needs to be passed here
                summary: [],
                // Data that you want to pass back to the notification window details block
                details: {
                    body: body,
                    host: host,
                    incidents: incidents
                }
            }
        });
    });
}

function destroyToken(options, _, cb) {
    let tokenHolder = getTokenFromCache(options);
    if (tokenHolder) {
        tokenHolder.counter--;
        if (tokenHolder.counter < 1) {
            let uri = options.url + '/rest/session';

            request({
                method: 'DELETE',
                uri: uri
            }, function (err, _, body) {
                if (err) {
                    if (cb) {
                        cb(_createJsonErrorPayload("Session is being Destroyed", body, '401', '2A', 'Session Terminated', {
                            err: err
                        }));
                        return;
                    }
                }

                if (cb) {
                    deleteToken(options);
                    cb(null, null);
                }
            });
        } else {
            // there are still requests using the token so we need to leave it alone
            if (cb) {
                cb(null, null);
            }
        }
    } else {
        Logger.warn('destroy was called on a token that did not exist in the cache, this should never happen');
    }
}


function _isLookupMiss(response) {
    return response.statusCode === 404 || response.statusCode === 500;
}

function _isApiError(err, response, body, entityValue) {
    if (err) {
        return err;
    }

    if (response.statusCode === 500) {
        return _createJsonErrorPayload("Malinformed Request", null, '500', '1', 'Malinformed Request', {
            err: err
        });
    }

    // Any code that is not 200 and not 404 (missed response), we treat as an error
    if (response.statusCode !== 200 && response.statusCode !== 404) {
        return body;
    }

    return null;
}

// function that takes the ErrorObject and passes the error message to the notification window
var _createJsonErrorPayload = function (msg, pointer, httpCode, code, title, meta) {
    return {
        errors: [
            _createJsonErrorObject(msg, pointer, httpCode, code, title, meta)
        ]
    }
};

var _createJsonErrorObject = function (msg, pointer, httpCode, code, title, meta) {
    let error = {
        detail: msg,
        status: httpCode.toString(),
        title: title,
        code: 'DORG_' + code.toString()
    };

    if (pointer) {
        error.source = {
            pointer: pointer
        };
    }

    if (meta) {
        error.meta = meta;
    }

    return error;
};

function validateOptions(userOptions, cb) {
    let errors = [];
    if (typeof userOptions.url.value !== 'string' ||
        (typeof userOptions.url.value === 'string' && userOptions.url.value.length === 0)) {
        errors.push({
            key: 'url',
            message: 'You must provide a Resilient URl'
        })
    }

    cb(null, errors);
}

function onMessage(payload, options, callback) {
    Logger.trace('got options for post', { options: options });

    createToken(options, function (err, token) {
        if (err) {
            destroyToken(options, token);
            Logger.error('error getting token', { err: err });
            callback({ err: err });
            return;
        }

        let data = payload.data;

        let requestOptions = {
            uri: `${options.url}/rest/orgs/${options.org_id}/incidents/${data.inc_id}/comments`,
            method: 'POST',
            headers: { 'X-sess-id': token.token, 'Cookie': token.cookies },
            body: {
                "text": data.note
            },
            json: true
        };

        Logger.trace({ requestOptions: requestOptions });

        requestWithDefaults(options, requestOptions, (err, resp, body) => {
            if (err || resp.statusCode !== 200) {
                destroyToken(options, token);
                Logger.error('error posting note', { err: err, statusCode: resp ? resp.statusCode : "unknown", requestOptions: requestOptions, payload: payload, body: body });
                callback({ err: err, statusCode: resp ? resp.statusCode : "unknown", body: body });
                return;
            }

            destroyToken(options, token);
            callback(null, {});
        });
    });
}

module.exports = {
    doLookup: doLookup,
    startup: startup,
    onMessage: onMessage,
    validateOptions: validateOptions
};
