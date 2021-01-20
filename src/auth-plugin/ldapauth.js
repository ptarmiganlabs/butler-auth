const globals = require('../lib/globals');
const rateLimit = require('../lib/ratelimit');
const QlikAuth = require('../lib/qlik-auth').QlikAuth;
var LdapStrategy = require('passport-ldapauth');
const fs = require('fs');

// --------------------------------------------------------
// Using auth library: https://github.com/vesse/passport-ldapauth
// --------------------------------------------------------

// TODO: Add input validation

var OPTS = {
    server: {
        url:
            globals.config.get('ButlerAuth.authProvider.ldap.ldapServer.host') +
            ':' +
            globals.config.get('ButlerAuth.authProvider.ldap.ldapServer.port'),
        bindDN: globals.config.get('ButlerAuth.authProvider.ldap.ldapServer.bindUser'),
        bindCredentials: globals.config.get('ButlerAuth.authProvider.ldap.ldapServer.bindPwd'),
        searchBase: globals.config.get('ButlerAuth.authProvider.ldap.ldapServer.searchBase'),
        searchFilter: globals.config.get('ButlerAuth.authProvider.ldap.ldapServer.searchFilter'),
        searchAttributes: ['sAMAccountName', 'displayName', 'givenName', 'sn', 'mail', 'dn'],
        tlsOptions: {},
    },
};

if (
    globals.config.has('ButlerAuth.authProvider.ldap.ldapServer.tls.ca') &&
    globals.config.get('ButlerAuth.authProvider.ldap.ldapServer.tls.ca') != undefined
) {
    OPTS.server.tlsOptions = {
        ca: fs.readFileSync(globals.config.get('ButlerAuth.authProvider.ldap.ldapServer.tls.ca')),
    };
}

var authPath = '/auth/ldap';

// Static function for setting up REST endpoint
function registerAuthEndpoint(passport, appRest, appWeb) {
    globals.logger.info('AUTH-LDAP: Setting up endpoints.');

    passport.use(new LdapStrategy(OPTS));

    // Endpoint called by Qlik Sense virtual proxy
    appRest.get(authPath, rateLimit.limiterRest, (req, res, next) => {
        globals.logger.debug('AUTH-LDAP: GET call.');

        let redirectURI = '';
        redirectURI = `${globals.config.get('ButlerAuth.authProvider.ldap.url')}/auth-ldap.html?proxyRestUri=${
            req.query.proxyRestUri
        }&targetId=${req.query.targetId}`;

        res.redirect(redirectURI);
    });

    appWeb.post(authPath, function (req, res, next) {
        try {
            passport.authenticate('ldapauth', { session: false }, function (err, user, info) {
                if (err) {
                    return next(err);
                }
                if (!user) {
                    globals.logger.warn(`AUTH-LDAP: User not found in LDAP or pwd incorrect: ${req.body.username}`);

                    return res.redirect(
                        `/auth-ldap.html?proxyRestUri=${req.body.proxyRestUri}&targetId=${req.body.targetId}&authFailed=true`,
                    );
                }

                globals.logger.verbose(
                    `AUTH-LDAP: User successfully authenticated in LDAP: ${JSON.stringify(user, null, 2)}`,
                );
                globals.logger.debug('AUTH-LDAP: POST call.');
                globals.logger.debug(`Body: ${JSON.stringify(req.body, null, 2)}`);

                let qlikAuth = new QlikAuth(req.body.proxyRestUri, req.body.targetId);

                // Define user directory, user identity and attributes
                let qlikSenseProfile = {
                    userDirectory: globals.config.get('ButlerAuth.authProvider.ldap.userDirectory'),
                    userId: req.body.username,
                    attributes: [],
                };

                // Get Qlik Sense ticket
                qlikAuth.requestTicket(req, res, qlikSenseProfile);
                globals.logger.info(`AUTH-LDAP: Sense ticket retrieved for ${JSON.stringify(qlikSenseProfile)}`);

                return;
            })(req, res, next);
        } catch (err) {
            globals.logger.error(`AUTH-LDAP: LDAP authentication failed: ${err}`);
        }

        return;
    });
}

module.exports = {
    registerAuthEndpoint,
};
