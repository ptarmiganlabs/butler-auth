const globals = require('../lib/globals');
const QlikAuth = require('../lib/qlik-auth').QlikAuth;
var KeycloakStrategy = require('@exlinc/keycloak-passport');

// --------------------------------------------------------
// Using auth library: https://github.com/exlinc/keycloak-passport
// --------------------------------------------------------

// TODO: Add input validation

var authPath = '/auth/keycloak';
var authPathCallback = '/auth/keycloak/redirect';

// Static function for setting up REST endpoint
function registerAuthEndpoint(passport, restServer) {
    globals.logger.info('AUTH-KEYCLOAK: Setting up endpoints.');

    passport.use(
        new KeycloakStrategy(
            {
                host: globals.config.get('ButlerAuth.authProvider.keycloak.host'),
                realm: globals.config.get('ButlerAuth.authProvider.keycloak.realm'),
                authorizationURL: globals.config.get('ButlerAuth.authProvider.keycloak.authorizationURL'),
                tokenURL: globals.config.get('ButlerAuth.authProvider.keycloak.tokenURL'),
                userInfoURL: globals.config.get('ButlerAuth.authProvider.keycloak.userInfoURL'),
                clientID: globals.config.get('ButlerAuth.authProvider.keycloak.clientId'),
                clientSecret: globals.config.get('ButlerAuth.authProvider.keycloak.clientSecret'),
                callbackURL: authPathCallback
            },
            function (accessToken, refreshToken, profile, cb) {

                return cb(null, profile);
            },
        ),
    );

    // Endpoint called by Qlik Sense virtual proxy
    restServer.get(
        authPath,
        (req, res, next) => {
            globals.logger.debug('AUTH-KEYCLOAK: GET call.');

            try {
                // Save Qlik Sense callback info in user's session
                req.session.proxyRestUri = req.query.proxyRestUri;
                req.session.targetId = req.query.targetId;

                next();
            } catch (err) {
                globals.logger.error(`AUTH-KEYCLOAK: Could not set session data: ${err}`);
            }
        },
        passport.authenticate('Keycloak', { failureRedirect: authPath }),
    );

    // Callback called by Keycloak after successful auth
    restServer.get(authPathCallback, passport.authenticate('Keycloak'), (req, res, next) => {
        globals.logger.debug('AUTH-KEYCLOAK: GET callback from Keycloak.');

        try {
            let qlikAuth = new QlikAuth(req.session.proxyRestUri, req.session.targetId);

            // Define user directory, user identity and attributes
            let qlikSenseProfile = {};
            if (req.user.email.length > 0) {
                let newUserId = req.user.email;
                
                // Should email domain be removed?
                if (globals.config.get('ButlerAuth.authProvider.keycloak.userIdShort')) {
                    newUserId = newUserId.split('@')[0];
                }

                qlikSenseProfile = {
                    userDirectory: globals.config.get('ButlerAuth.authProvider.keycloak.userDirectory'),
                    userId: newUserId,
                    attributes: [],
                };
            } else {
                // No userID (=email address) returned from Keycloak => we can't request a token from Sense.
                throw 'No user ID returned from Keycloak';
            }

            // Get Qlik Sense ticket
            qlikAuth.requestTicket(req, res, qlikSenseProfile);
            globals.logger.info(`AUTH-KEYCLOAK: Sense ticket retrieved for ${JSON.stringify(qlikSenseProfile)}`);

            return;
        } catch (err) {
            globals.logger.error(`AUTH-KEYCLOAK: Keycloak authentication failed: ${err}`);
        }
    });
}

module.exports = {
    registerAuthEndpoint,
};
