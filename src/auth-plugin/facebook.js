const globals = require('../lib/globals');
const QlikAuth = require('../lib/qlik-auth').QlikAuth;
var FacebookStrategy = require('passport-facebook').Strategy;

// --------------------------------------------------------
// Using auth library: https://github.com/jaredhanson/passport-facebook
// --------------------------------------------------------

// TODO: Add input validation

var authPath = '/auth/facebook';
var authPathCallback = '/auth/facebook/redirect';

// Static function for setting up REST endpoint
function registerAuthEndpoint(passport, restServer) {
    globals.logger.info('AUTH-FACEBOOK: Setting up endpoints.');

    passport.use(
        new FacebookStrategy(
            {
                clientID: globals.config.get('ButlerAuth.authProvider.facebook.clientId'),
                clientSecret: globals.config.get('ButlerAuth.authProvider.facebook.clientSecret'),
                callbackURL: authPathCallback,
                profileFields: [
                    'id',
                    'email',
                    'displayName',
                ],
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
            globals.logger.debug('AUTH-FACEBOOK: GET call.');

            try {
                // Save Qlik Sense callback info in user's session
                req.session.proxyRestUri = req.query.proxyRestUri;
                req.session.targetId = req.query.targetId;

                next();
            } catch (err) {
                globals.logger.error(`AUTH-FACEBOOK: Could not set session data: ${err}`);
            }
        },

        passport.authenticate('facebook', { failureRedirect: authPath }),
    );

    // Callback called by Facebook after successful auth
    restServer.get(authPathCallback, passport.authenticate('facebook'), (req, res, next) => {
        globals.logger.debug('AUTH-FACEBOOK: GET callback from Facebook.');

        try {
            let qlikAuth = new QlikAuth(req.session.proxyRestUri, req.session.targetId);

            // Define user directory, user identity and attributes
            let qlikSenseProfile = {};
            if (req.user.emails.length > 0) {
                let newUserId = req.user.emails[0].value;
                
                // Should email domain be removed?
                if (globals.config.get('ButlerAuth.authProvider.facebook.userIdShort')) {
                    newUserId = newUserId.split('@')[0];
                }

                qlikSenseProfile = {
                    userDirectory: globals.config.get('ButlerAuth.authProvider.facebook.userDirectory'),
                    userId: newUserId,
                    attributes: [],
                };
            } else {
                // No userID (=email address) returned from Facebook => we can't request a token from Sense.
                throw 'No user ID returned from Facebook';
            }

            // Get Qlik Sense ticket
            qlikAuth.requestTicket(req, res, qlikSenseProfile);
            globals.logger.info(`AUTH-FACEBOOK: Sense ticket retrieved for ${JSON.stringify(qlikSenseProfile)}`);

            return;
        } catch (err) {
            globals.logger.error(`AUTH-FACEBOOK: Facebook authentication failed: ${err}`);
        }
    });
}

module.exports = {
    registerAuthEndpoint,
};
