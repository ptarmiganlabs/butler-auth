const globals = require('../lib/globals');
const QlikAuth = require('../lib/qlik-auth').QlikAuth;
var MicrosoftStrategy = require('passport-microsoft').Strategy;

// --------------------------------------------------------
// Using auth library: https://github.com/seanfisher/passport-microsoft
// --------------------------------------------------------

// TODO: Add input validation

var authPath = '/auth/microsoft';
var authPathCallback = '/auth/microsoft/redirect';

// Static function for setting up REST endpoint
function registerAuthEndpoint(passport, restServer) {
    globals.logger.info('AUTH-MICROSOFT: Setting up endpoints.');

    passport.use(
        new MicrosoftStrategy(
            {
                clientID: globals.config.get('ButlerAuth.authProvider.microsoft.clientId'),
                clientSecret: globals.config.get('ButlerAuth.authProvider.microsoft.clientSecret'),
                callbackURL: authPathCallback,
                scope: [
                    'user.read',
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
            globals.logger.debug('AUTH-MICROSOFT: GET call.');

            try {
                // Save Qlik Sense callback info in user's session
                req.session.proxyRestUri = req.query.proxyRestUri;
                req.session.targetId = req.query.targetId;

                next();
            } catch (err) {
                globals.logger.error(`AUTH-MICROSOFT: Could not set session data: ${err}`);
            }
        },

        passport.authenticate('microsoft', { failureRedirect: authPath }),
    );

    // Callback called by Microsoft after successful auth
    restServer.get(authPathCallback, passport.authenticate('microsoft'), (req, res, next) => {
        globals.logger.debug('AUTH-MICROSOFT: GET callback from Microsoft.');

        try {
            let qlikAuth = new QlikAuth(req.session.proxyRestUri, req.session.targetId);

            // Define user directory, user identity and attributes
            let qlikSenseProfile = {};
            if (req.user.emails.length > 0) {
                let newUserId = req.user.emails[0].value;
                
                // Should email domain be removed?
                if (globals.config.get('ButlerAuth.authProvider.microsoft.userIdShort')) {
                    newUserId = newUserId.split('@')[0];
                }

                qlikSenseProfile = {
                    userDirectory: globals.config.get('ButlerAuth.authProvider.microsoft.userDirectory'),
                    userId: newUserId,
                    attributes: [],
                };
            } else {
                // No userID (=email address) returned from Microsoft => we can't request a token from Sense.
                throw 'No user ID returned from Microsoft';
            }

            // Get Qlik Sense ticket
            qlikAuth.requestTicket(req, res, qlikSenseProfile);
            globals.logger.info(`AUTH-MICROSOFT: Sense ticket retrieved for ${JSON.stringify(qlikSenseProfile)}`);

            return;
        } catch (err) {
            globals.logger.error(`AUTH-MICROSOFT: Microsoft authentication failed: ${err}`);
        }
    });
}

module.exports = {
    registerAuthEndpoint,
};
