# restify-auth-ldap [![Build Status](https://travis-ci.org/bimedia-fr/restify-auth-ldap.svg?branch=master)](https://travis-ci.org/bimedia-fr/restify-auth-ldap) [![NPM version](https://img.shields.io/npm/v/restify-auth-ldap.svg)](https://www.npmjs.com/package/restify-auth-ldap)

Provide a LDAP authentication middleware for restify

### Installation

```sh
npm install --save restify-auth-ldap
```

### Usage
Restify-auth-ldap need a cache instance to avoid to making too many requests to the LDAP server.
Only 
```js
cache.get(key);
``` 
and 
```js
cache.set(key, value);
```
methods are used.

We recommend using the [lru-cache](https://github.com/isaacs/node-lru-cache)  lib.

```js
var auth = require('restify-auth-ldap');

var lruCache = require('lru-cache');

var options = {
    cache : lruCache({
        max: 10,
        maxAge: 300000
    }),
    ldap : {
        opts : { // LDAP server config, passed to ldapjs instance
            url : 'ldap://127.0.0.1:389'
        },
        user : {  // UserDN is: uid=[USERNAME],ou=People,dc=is,dc=bimedia-dev,dc=com 
            DN : 'ou=People,dc=is,dc=bimedia-dev,dc=com',
            attribute : 'uid'
        },
        search : { // Search userDN in member attribute of cn=App,ou=Applications,ou=Groups,dc=is,dc=bimedia-dev,dc=com
            base : 'cn=App,ou=Applications,ou=Groups,dc=is,dc=bimedia-dev,dc=com',
            options : {
                scope : 'sub',
                attributes : [ 'member' ]
            }
        }
    }
};

var middleware = auth(options);

restify.use(middleware);
```