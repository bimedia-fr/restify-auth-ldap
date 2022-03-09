# restify-auth-ldap [![Build Status](https://travis-ci.org/bimedia-fr/restify-auth-ldap.svg?branch=master)](https://travis-ci.org/bimedia-fr/restify-auth-ldap) [![NPM version](https://img.shields.io/npm/v/restify-auth-ldap.svg)](https://www.npmjs.com/package/restify-auth-ldap)

Provide a LDAP authentication middleware for restify

### Installation

```sh
npm install --save restify-auth-ldap
```

### Usage

```js
var auth = require('restify-auth-ldap');

var options = {
    connection : 'ldap://127.0.0.1:389',
    user : {  
        dn : 'uid=binduser,ou=People,dc=is,dc=bimedia-dev,dc=com',
        password : 'bindpassword'
    },
    search : { // Search userDN in member attribute of cn=App,ou=Applications,ou=Groups,dc=is,dc=bimedia-dev,dc=com
        base : 'cn=App,ou=Applications,ou=Groups,dc=is,dc=bimedia-dev,dc=com'
    }
};

restify.use(auth(options));
```

### Configuration

* `connection`: ldap connection url
* `user.dn`: user to connect to ldap server
* `user.password`: password to connect to ldap server
* `search.base`: search user from this tree
* `search.filter` (optional): search filter - default '(uid=%s)'
* `search.scope` (optional): search scope - default 'sub'
* `search.attributes` (optional): search attributes - default  [ 'member' ]
* `cache` (optional): cache instance - default no cache
* `useBrowserAuth.realm` (optional): reply on missing auth with `www-authenticate` header (false to disable)

#### enable cache

Restify-auth-ldap supports cache to avoid making too many requests to the LDAP server.
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
    connection : 'ldap://127.0.0.1:389',
    user : {  
        dn : 'uid=binduser,ou=People,dc=is,dc=bimedia-dev,dc=com',
        password : 'bindpassword'
    },
    search : { // Search userDN in member attribute of cn=App,ou=Applications,ou=Groups,dc=is,dc=bimedia-dev,dc=com
        base : 'cn=App,ou=Applications,ou=Groups,dc=is,dc=bimedia-dev,dc=com'
    }
};
```