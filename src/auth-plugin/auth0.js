const globals = require('../lib/globals');
const QlikAuth = require('../lib/qlik-auth').QlikAuth;
const Auth0Strategy = require('passport-auth0');

// --------------------------------------------------------
// Using auth library: https://github.com/auth0/passport-auth0
// --------------------------------------------------------

// TODO: Add input validation

var authPath = '/auth/auth0';
var authPathCallback = '/auth/auth0/redirect';

// Static function for setting up REST endpoint
function registerAuthEndpoint(passport, restServer) {
    globals.logger.info('AUTH-AUTH0: Setting up endpoints.');

    passport.use(
        new Auth0Strategy(
            {
                domain: globals.config.get('ButlerAuth.authProvider.auth0.issuerBaseURL'),
                clientID: globals.config.get('ButlerAuth.authProvider.auth0.clientId'),
                clientSecret: globals.config.get('ButlerAuth.authProvider.auth0.clientSecret'),
                callbackURL: authPathCallback,
                state: true,
                passReqToCallback: false,
                scope: 'openid email profile',
            },
            function (accessToken, refreshToken, extraParams, profile, cb) {
                return cb(null, profile);
            },
        ),
    );

    // Endpoint called by Qlik Sense virtual proxy
    restServer.get(
        authPath,
        (req, res, next) => {
            globals.logger.debug('AUTH-AUTH0: GET call.');

            try {
                // Save Qlik Sense callback info in user's session
                req.session.proxyRestUri = req.query.proxyRestUri;
                req.session.targetId = req.query.targetId;

                next();
            } catch (err) {
                globals.logger.error(`AUTH-AUTH0: Could not set session data: ${err}`);
            }
        },
        passport.authenticate('auth0', {}),
    );

    // Callback called by Auth0 after successful auth
    restServer.get(authPathCallback, passport.authenticate('auth0'), (req, res, next) => {
        globals.logger.debug('AUTH-AUTH0: GET callback from Auth0.');

        try {
            let qlikAuth = new QlikAuth(req.session.proxyRestUri, req.session.targetId);

            // Define user directory, user identity and attributes
            let qlikSenseProfile = {};
            if (req.user.emails != undefined && req.user.emails.length > 0) {
                let newUserId = req.user.emails[0].value;
                
                // Should email domain be removed?
                if (globals.config.get('ButlerAuth.authProvider.auth0.userIdShort')) {
                    newUserId = newUserId.split('@')[0];
                }

                qlikSenseProfile = {
                    userDirectory: globals.config.get('ButlerAuth.authProvider.auth0.userDirectory'),
                    userId: newUserId,
                    attributes: [],
                };
            } else {
                // No userID (=email address) returned from Auth0 => we can't request a token from Sense.
                throw 'No user ID returned from Auth0';
            }

            // Get Qlik Sense ticket
            qlikAuth.requestTicket(req, res, qlikSenseProfile);
            globals.logger.info(`AUTH-AUTH0: Sense ticket retrieved for ${JSON.stringify(qlikSenseProfile)}`);

            return;
        } catch (err) {
            globals.logger.error(`AUTH-AUTH0: Auth0 authentication failed: ${err}`);
        }
    });
}

module.exports = {
    registerAuthEndpoint,
};
