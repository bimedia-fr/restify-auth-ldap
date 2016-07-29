/*jslint node : true, nomen: true, plusplus: true, vars: true, eqeq: true,*/
"use strict";

var ldap = require('ldapjs');
var async = require('async');
var errors = require('restify-errors');

/*
Options = { 
    cache: cache instance, 
    ldap: { 
        opts: {
            url : '' 
        }, 
        user: { 
            DN: 'ou=People,dc=is,dc=bimedia-dev,dc=com', 
            attribute: 'uid' 
        },
        search: {
            base : 'cn=ODP,ou=Applications,ou=Groups,dc=is,dc=bimedia-dev,dc=com',
            options: {
                scope : 'sub',
                attributes: ['member']
            }
        } 
    } 
};
 */

module.exports = function(options) {
    
    var ldapClient = null;
    var cache = options.cache;
    
    return function(req, res, next) {
        // Check http headers
        if(!req.headers.authorization) {
            res.setHeader('WWW-Authenticate', 'Basic realm="Basic realm"');
            return next(new errors.UnauthorizedError());            
        }
        var header = req.headers.authorization.split(' ');
        if(header[0] != 'Basic') {
            res.setHeader('WWW-Authenticate', 'Basic realm="Basic realm"');
            return next(new errors.UnauthorizedError());
        }
        var auth = new Buffer(header[1], 'base64').toString().split(':');
        if(auth.length != 2) {
            res.setHeader('WWW-Authenticate', 'Basic realm="Basic realm"');
            return next(new errors.UnauthorizedError());
        }
        
        // Check auth...
        var username = auth[0];
        var password = auth[1];
        
        var ldapUser = [[options.ldap.user.attribute, username].join('='),
                        options.ldap.user.DN].join(',');
        
        // Using LRU...
        var cachedPasswd = cache.get(ldapUser);
        if(cachedPasswd && password == cachedPasswd) {
            return next();
        }
        
        // Using LDAP...
        // Check if client exists...
        if(!ldapClient) {
            ldapClient = ldap.createClient(options.ldap.opts || {});
        }
    
        async.series([ function(cb) {
            // Bind with user...
            ldapClient.bind(ldapUser, password, function(err) {
                cb(err);
            });
        }, function(cb) {
            // Check groups...
            var users = [];
            options.ldap.search.options.filter = '(member='+ldapUser+')';
            ldapClient.search(options.ldap.search.base, options.ldap.search.options, function (err, res) {
                if (err) {
                    return cb(err);
                }

                res.on('searchEntry', function (entry) {
                    users.push(entry.object);
                });

                res.on('end', function () {
                    cb(null, users);
                });
            });
        } ], function(err, results) {
            ldapClient.unbind(function(err) {
                if(err) {
                    ldapClient.close();
                    ldapClient = null;
                }
            });
            
            // No error, and user found in right group
            if(!err && results[1] && results[1].length > 0) {
                cache.set(ldapUser, password);
                return next();
            }
            
            res.setHeader('WWW-Authenticate', 'Basic realm="Basic realm"');
            return next(new errors.UnauthorizedError());
        });
    }
}