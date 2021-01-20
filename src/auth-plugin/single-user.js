const globals = require('../lib/globals');
const QlikAuth = require('../lib/qlik-auth').QlikAuth;

// --------------------------------------------------------
// Using auth library: None
// --------------------------------------------------------

var authPath = '/auth/singleuser';

class AuthSingleUser {
    constructor() {}

    // Static function for setting up REST endpoint
    static registerAuthEndpoint(restServer) {
        restServer.get(authPath, (req, res, next) => {
            globals.logger.debug('AUTH-SINGLEUSER: Butler authenticator main endpoint called.');

            this.qlikAuth = new QlikAuth(req.query.proxyRestUri, req.query.targetId);

            // Define user directory, user identity and attributes
            this.qlikSenseProfile = {
                userDirectory: globals.config.get('ButlerAuth.authProvider.singleUser.userDirectory'),
                userId: globals.config.get('ButlerAuth.authProvider.singleUser.userId'),
                attributes: [],
            };

            // Get Qlik Sense ticket
            this.qlikAuth.requestTicket(req, res, this.qlikSenseProfile);
            globals.logger.info(`AUTH-SINGLEUSER: Sense ticket retrieved for ${JSON.stringify(this.qlikSenseProfile)}`);

            return;
        });
    }
}

module.exports = {
    AuthSingleUser,
};
