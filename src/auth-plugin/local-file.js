const globals = require('../lib/globals');
const QlikAuth = require('../lib/qlik-auth').QlikAuth;
var Strategy = require('passport-local').Strategy;
const yaml = require('js-yaml');
const fs = require('fs');
// const bcrypt = require('bcrypt');

// --------------------------------------------------------
// Using auth library: https://github.com/jaredhanson/passport-local
// --------------------------------------------------------

// TODO: Add input validation
// TODO: Hash passwords using https://github.com/kelektiv/node.bcrypt.js

var userArray = [];
var authPath = '/auth/localfile';

const saltRounds = 15;

async function userAuthenticate(username, password) {
    for (const user of userArray) {
        if (user.username == username && password == user.password) {
            // Match - authentication successful
            return true;
        }
    }

    // Didn't find a username/pwd match.
    return false;
}

function loadUserList() {
    // First load users from disk file
    try {
        if (globals.config.get('ButlerAuth.authProvider.localFile.userFile')) {
            let usersFile = globals.config.get('ButlerAuth.authProvider.localFile.userFile');
            userArray = yaml.load(fs.readFileSync(usersFile, 'utf8')).users;

            globals.logger.info('AUTH-LOCALFILE: Successfully loaded users from file.');
            globals.logger.debug(`AUTH-LOCALFILE: Users loaded from file: ${JSON.stringify(userArray, null, 2)}`);
        }
    } catch (err) {
        globals.logger.error(`AUTH-LOCALFILE: Failed loading schedules from file: ${err}`);
    }

    // TODO Add support for loading users from remote URL (e.g. private/secure Git server repo)
    // Then load users from remote file
    // try {
    //     if (globals.config.get('ButlerAuth.authProvider.localFile.userUrl')) {
    //         let usersURL = globals.config.get('ButlerAuth.authProvider.localFile.userUrl');

    //         userArray = yaml.load(fs.readFileSync(usersFile, 'utf8')).butlerSchedule;

    //         globals.logger.info('AUTH-LOCALFILE: Successfully loaded users from file.');
    //         globals.logger.debug(`AUTH-LOCALFILE: Users loaded from file: ${JSON.stringify(userArray, null, 2)}`);
    //     }
    // } catch (err) {
    //     globals.logger.error(`AUTH-LOCALFILE: Failed loading schedules from remote URL: ${err}`);
    // }
}

// Static function for setting up REST endpoint
function registerAuthEndpoint(passport, restServer, webServer) {
    globals.logger.info('AUTH-LOCALFILE: Setting up endpoints.');

    passport.use(
        new Strategy(function (username, password, done) {
            globals.logger.debug('AUTH-LOCALFILE: Authenticating.');

            // Does the user exist in list of allowed users?
            if (userAuthenticate(username, password)) {
                globals.logger.info(`AUTH-LOCALFILE: Successful auth for user: ${username}`);
                return done(null, username);
            } else {
                globals.logger.warn(`AUTH-LOCALFILE: Unsuccessful auth for user: ${username}`);
                return done(null, false, { message: 'Incorrect username or password.' });
            }
        }),
    );

    globals.logger.info('AUTH-LOCALFILE: Loading user list.');
    loadUserList();

    // Endpoint called by Qlik Sense virtual proxy
    restServer.get(authPath, (req, res, next) => {
        globals.logger.debug('AUTH-LOCALFILE: GET call.');

        let redirectURI = '';
        redirectURI = `${globals.config.get(
            'ButlerAuth.authProvider.localFile.url',
        )}/auth-localfile.html?proxyRestUri=${req.query.proxyRestUri}&targetId=${req.query.targetId}`;

        res.redirect(redirectURI);
    });

    webServer.post(authPath, function (req, res, next) {
        passport.authenticate('local', function (err, user, info) {
            if (err) {
                return next(err);
            }
            if (!user) {
                globals.logger.warn(`AUTH-LOCALFILE: User not found in LDAP or pwd incorrect: ${req.body.username}`);

                return res.redirect(
                    `/auth-localfile.html?proxyRestUri=${req.body.proxyRestUri}&targetId=${req.body.targetId}&authFailed=true`,
                );
            }

            globals.logger.verbose(
                `AUTH-LOCALFILE: User successfully authenticated in LDAP: ${JSON.stringify(user, null, 2)}`,
            );

            globals.logger.debug('AUTH-LOCALFILE: POST call.');
            globals.logger.debug(`Body: ${JSON.stringify(req.body, null, 2)}`);

            let qlikAuth = new QlikAuth(req.body.proxyRestUri, req.body.targetId);

            // Define user directory, user identity and attributes
            let qlikSenseProfile = {
                userDirectory: globals.config.get('ButlerAuth.authProvider.localFile.userDirectory'),
                userId: req.body.username,
                attributes: [],
            };

            // Get Qlik Sense ticket
            qlikAuth.requestTicket(req, res, qlikSenseProfile);
            globals.logger.info(`AUTH-LOCALFILE: Sense ticket retrieved for ${JSON.stringify(qlikSenseProfile)}`);

            return;
        })(req, res, next);

        return;
    });
}

module.exports = {
    registerAuthEndpoint,
};
