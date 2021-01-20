const globals = require('../lib/globals');
const QlikAuth = require('../lib/qlik-auth').QlikAuth;
var GoogleStrategy = require('passport-google-oauth20').Strategy;

// --------------------------------------------------------
// Using auth library: https://github.com/jaredhanson/passport-google-oauth2
// --------------------------------------------------------

// TODO: Add input validation

/**
 * To use OAuth2 authentication, we need access to a a CLIENT_ID, CLIENT_SECRET and REDIRECT_URI.
 * To get these credentials for your application, visit https://console.cloud.google.com/apis/credentials.
 */

var authPath = '/auth/google';
var authPathCallback = '/auth/google/redirect';

// Static function for setting up REST endpoint
function registerAuthEndpoint(passport, restServer) {
    globals.logger.info('AUTH-GOOGLEOAUTH: Setting up endpoints.');

    passport.use(
        new GoogleStrategy(
            {
                clientID: globals.config.get('ButlerAuth.authProvider.google.clientId'),
                clientSecret: globals.config.get('ButlerAuth.authProvider.google.clientSecret'),
                callbackURL: authPathCallback,
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
            globals.logger.debug('AUTH-GOOGLEOAUTH: GET call.');

            try {
                // Save Qlik Sense callback info in user's session
                req.session.proxyRestUri = req.query.proxyRestUri;
                req.session.targetId = req.query.targetId;

                next();
            } catch (err) {
                globals.logger.error(`AUTH-GOOGLEOAUTH: Could not set session data: ${err}`);
            }
        },

        passport.authenticate('google', { scope: ['profile', 'email'], failureRedirect: authPath }),
    );

    // Callback called by Google after successful auth
    restServer.get(authPathCallback, passport.authenticate('google'), (req, res, next) => {
        globals.logger.debug('AUTH-GOOGLEOAUTH: GET callback from Google.');

        try {
            let qlikAuth = new QlikAuth(req.session.proxyRestUri, req.session.targetId);

            // Define user directory, user identity and attributes
            let qlikSenseProfile = {};
            if (req.user.emails.length > 0) {
                let newUserId = req.user.emails[0].value;
                
                // Should email domain be removed?
                if (globals.config.get('ButlerAuth.authProvider.google.userIdShort')) {
                    newUserId = newUserId.split('@')[0];
                }

                qlikSenseProfile = {
                    userDirectory: globals.config.get('ButlerAuth.authProvider.google.userDirectory'),
                    userId: newUserId,
                    attributes: [],
                };
            } else {
                // No userID (=email address) returned from Google => we can't request a token from Sense.
                throw 'No user ID returned from Google';
            }

            // Get Qlik Sense ticket
            qlikAuth.requestTicket(req, res, qlikSenseProfile);
            globals.logger.info(`AUTH-GOOGLEOAUTH: Sense ticket retrieved for ${JSON.stringify(qlikSenseProfile)}`);

            return;
        } catch (err) {
            globals.logger.error(`AUTH-GOOGLEOAUTH: Google authentication failed: ${err}`);
        }
    });
}

module.exports = {
    registerAuthEndpoint,
};
