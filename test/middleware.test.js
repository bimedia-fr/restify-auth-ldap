const middleware = require('../lib/index');
const assert = require('assert');
const mock = require('mock-require');

describe('restify auth ldap', () => {

    describe('without useBrowserAuth', () => {

        it('should reject request when no credentials are provided', async () => {
            let m  = middleware({});
            let req = {headers: {}}, res = {
                end: (data) => {
                    assert.strictEqual(res.statusCode, 401);
                    assert.strictEqual(data, 'Unauthorized');
                }
            };
            try {
                await m(req, res, () => {});
            }catch(e) {
                assert.ifError(e);
            }
        });

        it('should reject request with invalid auth scheme', async () => {
            let m  = middleware({});
            let req = {headers: {
                    authorization: 'Bearer plop'
                }}, res = {
                    end: (data) => {
                        assert.strictEqual(res.statusCode, 401);
                        assert.strictEqual(data, 'Unauthorized');
                    }
                };
            try {
                await m(req, res, () => {});
            }catch(e) {
                assert.ifError(e);
            }
        });

        it('should reject request when user is missing', async () => {
            let m  = middleware({});
            let req = {headers: {
                    authorization: 'Basic ' + Buffer.from(':pass', 'utf8').toString('base64')
                }}, res = {
                    end: (data) => {
                        assert.strictEqual(res.statusCode, 403);
                        assert.strictEqual(data, 'Forbidden');
                    }
                };
            try {
                await m(req, res, () => {});
            }catch(e) {
                assert.ifError(e);
            }
        });

        it('should reject request when pass is missing or empty', async () => {
            let m  = middleware({});
            let req = {headers: {
                    authorization: 'Basic ' + Buffer.from('user:', 'utf8').toString('base64')
                }}, res = {
                    end: (data) => {
                        assert.strictEqual(res.statusCode, 403);
                        assert.strictEqual(data, 'Forbidden');
                    }
                };
            try {
                await m(req, res, () => {});
            }catch(e) {
                assert.ifError(e);
            }
        });
    });

    describe('with useBrowserAuth', () => {

        it('should reject request when no credentials are provided', async () => {
            let m  = middleware({useBrowserAuth: {realm: 'toto'}});
            let headers = {};
            let req = {headers: {}}, res = {
                setHeader: (key, value) => {
                    headers[key] = value;
                },
                end: (data) => {
                    assert.strictEqual(res.statusCode, 401);
                    assert.strictEqual(data, 'Unauthorized');
                    assert.strictEqual(headers['WWW-Authenticate'], 'Basic realm="toto"');
                }
            };
            try {
                await m(req, res, () => {});
            }catch(e) {
                assert.ifError(e);
            }
        });

        it('should reject request with invalid auth scheme', async () => {
            let m  = middleware({useBrowserAuth: {realm: 'toto'}});
            let headers = {};
            let req = {headers: {
                    authorization: 'Bearer plop'
                }}, res = {
                    setHeader: (key, value) => {
                        headers[key] = value;
                    },
                    end: (data) => {
                        assert.strictEqual(res.statusCode, 401);
                        assert.strictEqual(data, 'Unauthorized');
                        assert.strictEqual(headers['WWW-Authenticate'], 'Basic realm="toto"');
                    }
                };
            try {
                await m(req, res, () => {});
            }catch(e) {
                assert.ifError(e);
            }
        });
    });

    describe('with cache', () => {
        it('should authorize request with valid user from cache scheme', async () => {
            let cache = {
                get: () => 'secret',
                set: () => {}
            };
            let m  = middleware({cache: cache, useBrowserAuth: {realm: 'toto'}});
            let req = {headers: {
                    authorization: 'Basic ' + Buffer.from('jerome:secret', 'utf8').toString('base64')
                }}, res = {
                };
            try {
                await m(req, res, () => {
                    assert.ok(req.auth);
                    assert.strictEqual(req.auth.basic.user, 'jerome');
                });
            }catch(e) {
                assert.ifError(e);
            }
        });
    });
    describe('with ldap queries', () => {
        it('should reject request on ldap error', async () => {
            mock('ldapjs-client', { createClient: function() {
                throw new Error('ldap error');
            }});
            let req = {headers: {
                    authorization: 'Basic ' + Buffer.from('user:', 'utf8').toString('base64')
                }}, res = {
                    end: (data) => {
                        assert.strictEqual(res.statusCode, 403);
                        assert.strictEqual(data, 'Forbidden');
                    }
                };
            let m  = middleware({useBrowserAuth: {realm: 'toto'}});
            try {
                await m(req, res, () => {
                    assert.fail('should have failed');
                });
            }catch(e) {
                assert.ifError(e);
            }
        });

        it('should reject request when user is not found', async () => {
            mock('ldapjs-client', { createClient: function() {
                return {
                    bind: () => {
                        return Promise.resolve();
                    },
                    search: () => {
                        return Promise.resolve([]);
                    }
                };
            }});
            let req = {headers: {
                    authorization: 'Basic ' + Buffer.from('user:', 'utf8').toString('base64')
                }}, res = {
                    end: (data) => {
                        assert.strictEqual(res.statusCode, 403);
                        assert.strictEqual(data, 'Forbidden');
                    }
                };
            let m  = middleware({connection: 'ldap://', search: {base:  '' }});
            try {
                await m(req, res, () => {
                    assert.fail('should have failed');
                });
            }catch(e) {
                assert.ifError(e);
            }
        });
        it('should reject request with wrong password', async () => {
            mock('ldapjs-client', { createClient: function() {
                return {
                    search: () => {
                        return Promise.resolve([{dn: 'jerome'}]);
                    },
                    bind: (user) => {
                        return user === 'admin' ? Promise.resolve() : Promise.reject(new Error('Invalid credentials'));
                    },
                    unbind: () => Promise.resolve()
                };
            }});
            let req = {headers: {
                    authorization: 'Basic ' + Buffer.from('user:', 'utf8').toString('base64')
                }}, res = {
                    end: (data) => {
                        assert.strictEqual(res.statusCode, 403);
                        assert.strictEqual(data, 'Forbidden');
                    }
                };
            let m  = middleware({connection: 'ldap://', user: { dn: 'admin', pass: ''}, search: {base:  '' }});
            try {
                await m(req, res, () => {
                    assert.fail('should have failed');
                });
            }catch(e) {
                assert.ifError(e);
            }
        });
        it('should authorize request with valid credentials', async () => {
            mock('ldapjs-client', { createClient: () => {
                return {
                    search: () => {
                        return Promise.resolve([{dn: 'jerome'}]);
                    },
                    bind: () => {
                        return Promise.resolve();
                    },
                    unbind: () => Promise.resolve()
                };
            }});
            let req = {headers: {
                    authorization: 'Basic ' + Buffer.from('jerome:secret', 'utf8').toString('base64')
                }}, res = {
                };
            let m  = middleware({connection: 'ldap://', user: { dn: 'admin', pass: ''}, search: {base:  '' }});
            try {
                await m(req, res, () => {
                    assert.ok(req.auth);
                    assert.strictEqual(req.auth.basic.user, 'jerome');
                });
            }catch(e) {
                assert.ifError(e);
            }
        });
    });
});
