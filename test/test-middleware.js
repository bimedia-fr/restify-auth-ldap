/*jslint node : true, nomen: true, plusplus: true, vars: true, eqeq: true,*/
"use strict";

var nodeunit = require('nodeunit');
var ldap = require('ldapjs');
var async = require('async');
var errors = require('restify-errors');
var lruCache = require('lru-cache');

var lib = require('../lib/index');

var server;

module.exports = {
    setUp : function(callback) {

        var self = this;
        var db = {};

        this.startServer = function(cb) {

            var SUFFIX = 'dc=is,dc=bimedia-dev,dc=com';
            

            server = ldap.createServer();

            function authorize(req, res, next) {
                /* Any user may search after bind, only cn=root has full power */
                var isSearch = (req instanceof ldap.SearchRequest);
                if (!req.connection.ldap.bindDN.equals('cn=root') && !isSearch)
                    return next(new ldap.InsufficientAccessRightsError());

                return next();
            }

            server.bind('cn=root', function(req, res, next) {
                if (req.dn.toString() !== 'cn=root'
                        || req.credentials !== 'secret')
                    return next(new ldap.InvalidCredentialsError());

                res.end();
                return next();
            });

            server.add(SUFFIX, authorize, function(req, res, next) {
                var dn = req.dn.toString();

                if (db[dn])
                    return next(new ldap.EntryAlreadyExistsError(dn));

                db[dn] = req.toObject().attributes;
                res.end();
                return next();
            });

            server.bind(SUFFIX, function(req, res, next) {
                var dn = req.dn.toString();
                if (!db[dn])
                    return next(new ldap.NoSuchObjectError(dn));

                if (!db[dn].userpassword)
                    return next(new ldap.NoSuchAttributeError('userPassword'));

                if (db[dn].userpassword.indexOf(req.credentials) === -1)
                    return next(new ldap.InvalidCredentialsError());

                res.end();
                return next();
            });

            server.compare(SUFFIX, authorize, function(req, res, next) {
                var dn = req.dn.toString();
                if (!db[dn])
                    return next(new ldap.NoSuchObjectError(dn));

                if (!db[dn][req.attribute])
                    return next(new ldap.NoSuchAttributeError(req.attribute));

                var matches = false;
                var vals = db[dn][req.attribute];
                for (var i = 0; i < vals.length; i++) {
                    if (vals[i] === req.value) {
                        matches = true;
                        break;
                    }
                }

                res.end(matches);
                return next();
            });

            server.del(SUFFIX, authorize, function(req, res, next) {
                var dn = req.dn.toString();
                if (!db[dn])
                    return next(new ldap.NoSuchObjectError(dn));

                delete db[dn];

                res.end();
                return next();
            });

            server.modify(SUFFIX, authorize,
                    function(req, res, next) {
                        var dn = req.dn.toString();
                        if (!req.changes.length)
                            return next(new ldap.ProtocolError(
                                    'changes required'));
                        if (!db[dn])
                            return next(new ldap.NoSuchObjectError(dn));

                        var entry = db[dn];

                        for (var i = 0; i < req.changes.length; i++) {
                            mod = req.changes[i].modification;
                            switch (req.changes[i].operation) {
                            case 'replace':
                                if (!entry[mod.type])
                                    return next(new ldap.NoSuchAttributeError(
                                            mod.type));

                                if (!mod.vals || !mod.vals.length) {
                                    delete entry[mod.type];
                                } else {
                                    entry[mod.type] = mod.vals;
                                }

                                break;

                            case 'add':
                                if (!entry[mod.type]) {
                                    entry[mod.type] = mod.vals;
                                } else {
                                    mod.vals.forEach(function(v) {
                                        if (entry[mod.type].indexOf(v) === -1)
                                            entry[mod.type].push(v);
                                    });
                                }

                                break;

                            case 'delete':
                                if (!entry[mod.type])
                                    return next(new ldap.NoSuchAttributeError(
                                            mod.type));

                                delete entry[mod.type];

                                break;
                            }
                        }

                        res.end();
                        return next();
                    });

            server.search(SUFFIX, authorize, function(req, res, next) {
                var dn = req.dn.toString();
                if (!db[dn])
                    return next(new ldap.NoSuchObjectError(dn));

                var scopeCheck;

                switch (req.scope) {
                case 'base':
                    if (req.filter.matches(db[dn])) {
                        res.send({
                            dn : dn,
                            attributes : db[dn]
                        });
                    }

                    res.end();
                    return next();

                case 'one':
                    scopeCheck = function(k) {
                        if (req.dn.equals(k))
                            return true;

                        var parent = ldap.parseDN(k).parent();
                        return (parent ? parent.equals(req.dn) : false);
                    };
                    break;

                case 'sub':
                    scopeCheck = function(k) {
                        return (req.dn.equals(k) || req.dn.parentOf(k));
                    };

                    break;
                }

                Object.keys(db).forEach(function(key) {
                    if (!scopeCheck(key))
                        return;

                    if (req.filter.matches(db[key])) {
                        res.send({
                            dn : key,
                            attributes : db[key]
                        });
                    }
                });

                res.end();
                return next();
            });

            server.listen(9001, '127.0.0.1', function() {
                //console.log('LDAP server listening at: ' + server.url);
                cb();
            });
        };

        this.fillServer = function(callb) {
            var client = ldap.createClient({
                url : 'ldap://127.0.0.1:9001'
            });

            var toDo = [];
            
            toDo.push(function(cb) {
                client.bind('cn=root', 'secret', cb);
            });
            toDo.push(function(cb) {
                var entry = {
                        uid: 'sboucontet340',
                        userpassword: 'secret!'
                };
                client.add('uid=sboucontet340,ou=People,dc=is,dc=bimedia-dev,dc=com', entry, cb);
            });
            toDo.push(function(cb) {
                var entry = {
                        cn: 'App',
                        member: ['uid=sboucontet340,ou=People,dc=is,dc=bimedia-dev,dc=com']
                };
                client.add('cn=App,ou=Applications,ou=Groups,dc=is,dc=bimedia-dev,dc=com', entry, cb);
            });
            toDo.push(function(cb) {
                var entry = {
                        cn: 'AppUnauthorized',
                        member: ['uid=otheruser,ou=People,dc=is,dc=bimedia-dev,dc=com']
                };
                client.add('cn=AppUnauthorized,ou=Applications,ou=Groups,dc=is,dc=bimedia-dev,dc=com', entry, cb);
            });
            toDo.push(function(cb) {
                client.bind('uid=sboucontet340,ou=People,dc=is,dc=bimedia-dev,dc=com', 'secret!', cb);
            });
            toDo.push(function(cb) {
                client.unbind(cb);
            });
            async.series(toDo, function(err, results) {
                callb();
            });
        };

        this.startServer(function() {
            self.fillServer(callback);
        });

    },
    'Success login with known user' : function(test) {

        test.expect(1);
        
        var cache = lruCache({
            max : 10,
            maxAge : 300000 // 5 minutes
        });

        var middleware = lib({
            cache : cache,
            ldap : {
                opts : {
                    url : 'ldap://127.0.0.1:9001'
                },
                user : {
                    DN : 'ou=People,dc=is,dc=bimedia-dev,dc=com',
                    attribute : 'uid'
                },
                search : {
                    base : 'cn=App,ou=Applications,ou=Groups,dc=is,dc=bimedia-dev,dc=com',
                    options : {
                        scope : 'sub',
                        attributes : [ 'member' ]
                    }
                }
            }
        });

        var b64 = new Buffer("sboucontet340:secret!").toString('base64');
        var req = {
            headers : {
                authorization : 'Basic ' + b64
            }
        };
        var res = {
            headers : [],
            setHeader : function(header, value) {
                this.headers[header] = value;
            }
        };
        var next = function(err) {
            test.equal(err, null);
            test.done();
        };

        middleware(req, res, next);
    },
    'Success login with known user (in cache)' : function(test) {

        test.expect(1);
        
        var cache = lruCache({
            max : 10,
            maxAge : 300000 // 5 minutes
        });
        
        cache.set('uid=anotherUser,ou=People,dc=is,dc=bimedia-dev,dc=com', 'anotherPass');

        var middleware = lib({
            cache : cache,
            ldap : {
                opts : {
                    url : 'ldap://127.0.0.1:9001'
                },
                user : {
                    DN : 'ou=People,dc=is,dc=bimedia-dev,dc=com',
                    attribute : 'uid'
                },
                search : {
                    base : 'cn=App,ou=Applications,ou=Groups,dc=is,dc=bimedia-dev,dc=com',
                    options : {
                        scope : 'sub',
                        attributes : [ 'member' ]
                    }
                }
            }
        });

        var b64 = new Buffer("anotherUser:anotherPass").toString('base64');
        var req = {
            headers : {
                authorization : 'Basic ' + b64
            }
        };
        var res = {
            headers : [],
            setHeader : function(header, value) {
                this.headers[header] = value;
            }
        };
        var next = function(err) {
            test.equal(err, null);
            test.done();
        };

        middleware(req, res, next);
    },
    'Fail to login with known user but bad password' : function(test) {
        
        test.expect(3);

        var cache = lruCache({
            max : 10,
            maxAge : 300000 // 5 minutes
        });

        var middleware = lib({
            cache : cache,
            ldap : {
                opts : {
                    url : 'ldap://127.0.0.1:9001'
                },
                user : {
                    DN : 'ou=People,dc=is,dc=bimedia-dev,dc=com',
                    attribute : 'uid'
                },
                search : {
                    base : 'cn=App,ou=Applications,ou=Groups,dc=is,dc=bimedia-dev,dc=com',
                    options : {
                        scope : 'sub',
                        attributes : [ 'member' ]
                    }
                }
            }
        });

        var b64 = new Buffer("sboucontet340:notsecret").toString('base64');
        var req = {
            headers : {
                authorization : 'Basic ' + b64
            }
        };
        var res = {
            headers : [],
            setHeader : function(header, value) {
                this.headers[header] = value;
            }
        };
        var next = function(err) {
            test.ok(err instanceof errors.UnauthorizedError);
            test.ok(res.headers['WWW-Authenticate']);
            test.equals(res.headers['WWW-Authenticate'], 'Basic realm="Basic realm"');
            test.done();
        };
        
        middleware(req, res, next);
    },
    'Fail to login with known user but bad password (in cache)' : function(test) {
        
        test.expect(3);

        var cache = lruCache({
            max : 10,
            maxAge : 300000 // 5 minutes
        });

        cache.set('uid=anotherUser,ou=People,dc=is,dc=bimedia-dev,dc=com', 'anotherPass');
        
        var middleware = lib({
            cache : cache,
            ldap : {
                opts : {
                    url : 'ldap://127.0.0.1:9001'
                },
                user : {
                    DN : 'ou=People,dc=is,dc=bimedia-dev,dc=com',
                    attribute : 'uid'
                },
                search : {
                    base : 'cn=App,ou=Applications,ou=Groups,dc=is,dc=bimedia-dev,dc=com',
                    options : {
                        scope : 'sub',
                        attributes : [ 'member' ]
                    }
                }
            }
        });

        var b64 = new Buffer("anotherUser:aBadPassword").toString('base64');
        var req = {
            headers : {
                authorization : 'Basic ' + b64
            }
        };
        var res = {
            headers : [],
            setHeader : function(header, value) {
                this.headers[header] = value;
            }
        };
        var next = function(err) {
            test.ok(err instanceof errors.UnauthorizedError);
            test.ok(res.headers['WWW-Authenticate']);
            test.equals(res.headers['WWW-Authenticate'], 'Basic realm="Basic realm"');
            test.done();
        };
        
        middleware(req, res, next);
    },
    'Fail to login with unknown user' : function(test) {
        
        test.expect(3);

        var cache = lruCache({
            max : 10,
            maxAge : 300000 // 5 minutes
        });

        var middleware = lib({
            cache : cache,
            ldap : {
                opts : {
                    url : 'ldap://127.0.0.1:9001'
                },
                user : {
                    DN : 'ou=People,dc=is,dc=bimedia-dev,dc=com',
                    attribute : 'uid'
                },
                search : {
                    base : 'cn=App,ou=Applications,ou=Groups,dc=is,dc=bimedia-dev,dc=com',
                    options : {
                        scope : 'sub',
                        attributes : [ 'member' ]
                    }
                }
            }
        });

        var b64 = new Buffer("jcreignou:secret!").toString('base64');
        var req = {
            headers : {
                authorization : 'Basic ' + b64
            }
        };
        var res = {
            headers : [],
            setHeader : function(header, value) {
                this.headers[header] = value;
            }
        };
        var next = function(err) {
            test.ok(err instanceof errors.UnauthorizedError);
            test.ok(res.headers['WWW-Authenticate']);
            test.equals(res.headers['WWW-Authenticate'], 'Basic realm="Basic realm"');
            test.done();
        };
        
        middleware(req, res, next);
    },
    'Fail to login with known user but not in required group' : function(test) {
        
        test.expect(3);

        var cache = lruCache({
            max : 10,
            maxAge : 300000 // 5 minutes
        });

        var middleware = lib({
            cache : cache,
            ldap : {
                opts : {
                    url : 'ldap://127.0.0.1:9001'
                },
                user : {
                    DN : 'ou=People,dc=is,dc=bimedia-dev,dc=com',
                    attribute : 'uid'
                },
                search : {
                    base : 'cn=AppUnauthorized,ou=Applications,ou=Groups,dc=is,dc=bimedia-dev,dc=com',
                    options : {
                        scope : 'sub',
                        attributes : [ 'member' ]
                    }
                }
            }
        });

        var b64 = new Buffer("sboucontet340:secret!").toString('base64');
        var req = {
            headers : {
                authorization : 'Basic ' + b64
            }
        };
        var res = {
            headers : [],
            setHeader : function(header, value) {
                this.headers[header] = value;
            }
        };
        var next = function(err) {
            test.ok(err instanceof errors.UnauthorizedError);
            test.ok(res.headers['WWW-Authenticate']);
            test.equals(res.headers['WWW-Authenticate'], 'Basic realm="Basic realm"');
            test.done();
        };
        
        middleware(req, res, next);
    },
    'Fail to login without auth infos' : function(test) {
        
        test.expect(3);

        var cache = lruCache({
            max : 10,
            maxAge : 300000 // 5 minutes
        });

        var middleware = lib({
            cache : cache,
            ldap : {
                opts : {
                    url : 'ldap://127.0.0.1:9001'
                },
                user : {
                    DN : 'ou=People,dc=is,dc=bimedia-dev,dc=com',
                    attribute : 'uid'
                },
                search : {
                    base : 'cn=App,ou=Applications,ou=Groups,dc=is,dc=bimedia-dev,dc=com',
                    options : {
                        scope : 'sub',
                        attributes : [ 'member' ]
                    }
                }
            }
        });

        var req = {
            headers : {}
        };
        var res = {
            headers : [],
            setHeader : function(header, value) {
                this.headers[header] = value;
            }
        };
        var next = function(err) {
            test.ok(err instanceof errors.UnauthorizedError);
            test.ok(res.headers['WWW-Authenticate']);
            test.equals(res.headers['WWW-Authenticate'], 'Basic realm="Basic realm"');
            test.done();
        };
        
        middleware(req, res, next);
    },
    tearDown : function(callback) {
        server.close();
        callback();
    }
}