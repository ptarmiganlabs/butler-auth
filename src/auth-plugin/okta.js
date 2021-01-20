const globals = require('../lib/globals');
const QlikAuth = require('../lib/qlik-auth').QlikAuth;
var OktaStrategy = require('passport-okta-oauth').Strategy;

// --------------------------------------------------------
// Using auth library: https://github.com/fischerdan/passport-okta-oauth
// --------------------------------------------------------

// TODO: Add input validation

var authPath = '/auth/okta';
var authPathCallback = '/auth/okta/redirect';

// Static function for setting up REST endpoint
function registerAuthEndpoint(passport, restServer) {
    globals.logger.info('AUTH-OKTA: Setting up endpoints.');

    passport.use(
        new OktaStrategy(
            {
                audience: globals.config.get('ButlerAuth.authProvider.okta.oktaDomain'),
                clientID: globals.config.get('ButlerAuth.authProvider.okta.clientId'),
                clientSecret: globals.config.get('ButlerAuth.authProvider.okta.clientSecret'),
                idp: globals.config.get('ButlerAuth.authProvider.okta.idp'),
                callbackURL: authPathCallback,
                scope: ['openid', 'email', 'profile'],
                response_type: 'code',
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
            globals.logger.debug('AUTH-OKTA: GET call.');

            try {
                // Save Qlik Sense callback info in user's session
                req.session.proxyRestUri = req.query.proxyRestUri;
                req.session.targetId = req.query.targetId;

                next();
            } catch (err) {
                globals.logger.error(`AUTH-OKTA: Could not set session data: ${err}`);
            }
        },
        passport.authenticate('okta', { failureRedirect: authPath }),
    );

    // Callback called by Okta after successful auth
    restServer.get(authPathCallback, passport.authenticate('okta'), (req, res, next) => {
        globals.logger.debug('AUTH-OKTA: GET callback from Okta.');

        try {
            let qlikAuth = new QlikAuth(req.session.proxyRestUri, req.session.targetId);

            // Define user directory, user identity and attributes
            let qlikSenseProfile = {};
            if (req.user.emails.length > 0) {
                let newUserId = req.user.emails[0].value;
                
                // Should email domain be removed?
                if (globals.config.get('ButlerAuth.authProvider.okta.userIdShort')) {
                    newUserId = newUserId.split('@')[0];
                }

                qlikSenseProfile = {
                    userDirectory: globals.config.get('ButlerAuth.authProvider.okta.userDirectory'),
                    userId: newUserId,
                    attributes: [],
                };
            } else {
                // No userID (=email address) returned from Okta => we can't request a token from Sense.
                throw 'No user ID returned from Okta';
            }

            // Get Qlik Sense ticket
            qlikAuth.requestTicket(req, res, qlikSenseProfile);
            globals.logger.info(`AUTH-OKTA: Sense ticket retrieved for ${JSON.stringify(qlikSenseProfile)}`);

            return;
        } catch (err) {
            globals.logger.error(`AUTH-OKTA: Okta authentication failed: ${err}`);
        }
    });
}

module.exports = {
    registerAuthEndpoint,
};
