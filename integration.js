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

    requestWithDefaults = request.defaults(defaults);
}


/**
 *
 * @param entities
 * @param options
 * @param cb
 */

 var createToken = function(options, cb) {

     let requestOptions = {
         uri: options.url + '/rest/session',
         method: 'POST',
         body: {
             "email": options.username,
             "password": options.password,
             "interactive": true
         },
         json: true,
         jar: true
     };

     Logger.trace({request: requestOptions}, "Checking the request options for auth token");

     requestWithDefaults(requestOptions, function (err, response, body) {
         let errorObject = _isApiError(err, response, body);
         Logger.trace({error: errorObject}, "Checking to see if there is an error in request");
         if (errorObject) {
             cb(errorObject);
             return;
         }

         Logger.trace({body: body}, "Body in auth token");

         let csrfToken = body.csrf_token;

         Logger.trace({auth: csrfToken}, "AuthToken Catch");

         cb(null, csrfToken);
     });
 };

function doLookup(entities, options, cb) {

    Logger.debug({options: options}, 'Options');
    let lookupResults = [];

    createToken (options, function (err, token) {
        if (err) {
            cb({
                detail: "Error Creating Session",
                err: err
            });
            destroyToken(options, token);
            return;
      }else{
        async.each(entities, function (entityObj, next) {
          if (entityObj.value !== null) {
                  _lookupEntity(entityObj, options, token, function (err, result) {
                    if (err) {
                        next(err);
                    } else {
                        Logger.debug({results: result}, "Logging results");
                        lookupResults.push(result);
                        next(null);
                    }
                });
          }else {
                lookupResults.push({entity: entityObj, data: null}); //Cache the missed results
                next(null);
            }
          }, function(err) {
            destroyToken(options, token);
            Logger.debug({lookup: lookupResults}, "Checking to see if the results are making its way to lookupresults");
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
        headers: {'X-sess-id': token},
        body: {
            "org_id": 220,
            "query": entityObj.value,
            "min_required_results": 0
        },
        json: true,
        jar: true
    };

    Logger.trace({data: requestOptions}, "Logging requestOptions");

    requestWithDefaults(requestOptions, function (err, response, body) {
        let errorObject = _isApiError(err, response, body, entityObj.value);
        Logger.trace({error: errorObject}, "Checking to see if there is an error in lookEntity request");
        if (errorObject) {
            cb(errorObject);
            return;
        }

      Logger.trace({resonse: response}, "Checking the reponse of the query");
      Logger.trace({data: body}, "Logging Body Data of the sha256");

        if (_.isNull(body)){
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

        body.results.forEach(function(data){
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

function destroyToken(options, token, cb) {

    let uri = options.url + '/rest/session';

    request({
        method: 'DELETE',
        uri: uri
    }, function (err, response, body) {
        if (err) {
            if (cb) {
                cb(_createJsonErrorPayload("Session is being Destroyed", body, '401', '2A', 'Session Terminated', {
                    err: err
                }));
                return;
            }
        }

        if (cb) {
            cb(null, null);
        }
    });
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

module.exports = {
    doLookup: doLookup,
    startup: startup,
    validateOptions: validateOptions
};
