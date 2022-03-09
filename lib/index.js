const util = require('util');
/*
Options = {
    cache: cache instance,
    useBrowserAuth : {
        realm: 'Basic realm'
    }
    connection: '',
    user: {
        dn: 'ou=People,dc=is,dc=bimedia-dev,dc=com',
        password: ''
    },
    connection: '',
    user: {
        dn: 'ou=People,dc=is,dc=bimedia-dev,dc=com',
        attribute: 'uid'
    },
    search: {
        base : 'cn=ODP,ou=Applications,ou=Groups,dc=is,dc=bimedia-dev,dc=com',
        options: {
            scope : 'sub',
            attributes: ['member']
        }
    }
};
 */

module.exports = function(options) {
    const ldap = require('ldapjs-client');
    let cache = options.cache;

    function UnauthorizedError (res, code = 401) {
        res.statusCode = code;
        if (options.useBrowserAuth) {
            res.setHeader('WWW-Authenticate', `Basic realm="${options.useBrowserAuth.realm}"`);
        }
        return res.end('Unauthorized');
    }

    function ForbiddenError (res, code = 403) {
        res.statusCode = code;
        return res.end('Forbidden');
    }

    function Authorize(req, user, next) {
        req.auth = { basic: { user } };
        return next();
    }

    function connect() {
        let client = ldap.createClient(options.connection);
        client.bind(options.user.dn, options.user.password);
        return client;
    }

    function searchUser(client, user) {
        let filterOpts = options.search.opts || {};
        let filter = util.format(filterOpts.filter || '(uid=%s)', user);
        let search = Object.assign({}, filterOpts || {}, {
            filter,
            scope : 'sub',
            attributes : [ 'member' ]
        });
        return client.search(options.search.base, search);
    }

    return async (req, res, next) => {
        const unauthorized = (code) => UnauthorizedError(res, code, options.useBrowserAuth);
        const forbidden = (code) => ForbiddenError(res, code);
        const authorize = (user) => Authorize(req, user, next);
        if(!req.headers.authorization) {
            return unauthorized();
        }
        const [ authType, base64 ] = req.headers.authorization.split(' ');
        if (authType !== 'Basic') {
            return unauthorized();
        }
        const [ user, pass ] = Buffer.from(base64, 'base64').toString().split(':');
        if (!(user && pass)) {
            return forbidden(403);
        }
        // Check auth Using cache
        const cachedPasswd = cache && cache.get(user);
        if (pass === cachedPasswd) {
            return authorize(user);
        }
        let client;
        try {
            client = await connect();
            let entries = await searchUser(client, user);
            if (entries.length === 0) {
                return forbidden(403);
            }
            await client.bind(entries[0].dn, pass);
            cache && cache.set(user, pass);
            return authorize(user);
        } catch (e) {
            return forbidden(403);
        } finally {
            await client && client.unbind();
        }
    };
};
