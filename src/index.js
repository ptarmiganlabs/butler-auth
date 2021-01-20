'use strict';

// Add dependencies
const globals = require('./lib/globals');
const heartbeat = require('./lib/heartbeat');
const serviceUptime = require('./lib/service_uptime');
const rateLimit = require('./lib/ratelimit');

const express = require('express');
var fs = require('fs');
var http = require('http');
var https = require('https');

// Load auth plugins
const authSingleUser = require('./auth-plugin/single-user').AuthSingleUser;
const authLocalFile = require('./auth-plugin/local-file');
const authLdapAuth = require('./auth-plugin/ldapauth');
const authGoogle = require('./auth-plugin/google');
const authFacebook = require('./auth-plugin/facebook');
const authMicrosoft = require('./auth-plugin/microsoft');
const authOkta = require('./auth-plugin/okta');
const authKeycloak = require('./auth-plugin/keycloak');
const authAuth0 = require('./auth-plugin/auth0');

var passport = require('passport');
var session = require('express-session'),
    bodyParser = require('body-parser'),
    FileStore = require('session-file-store')(session);


// var flash = require('express-flash');
// const flash = require('connect-flash');

async function main() {

    // Set up connection to Influxdb (if enabled)
    globals.initInfluxDB();

    if (globals.config.get('ButlerAuth.uptimeMonitor.enable') == true) {
        serviceUptime.serviceUptimeStart();
    }


    // Create appRest object

    // In order to restore authentication state across HTTP requests, Passport needs
    // to serialize users into and deserialize users out of the session.  In an
    // application with it's own user database, this would typically be as simple as
    // supplying the user ID when serializing, and querying the user record by ID
    // from the database when deserializing.
    // In the current case we're relying on a user directory in Qlik Sense instead,
    // and we can just serialize/deserialize the complete user profile.
    passport.serializeUser(function (user, cb) {
        cb(null, user);
    });

    passport.deserializeUser(function (obj, cb) {
        cb(null, obj);
    });

    const appRest = express();
    const appWeb = express();

    // Initialize Passport and restore authentication state, if any, from the session.
    appRest.use(passport.initialize());
    // appRest.use(passport.session());

    appWeb.use(express.static('html'));

    // Options for file based sessions
    const fileStoreOptions = {};

    appWeb.use(require('morgan')('combined'));
    appWeb.use(bodyParser.urlencoded({ extended: true }));
    // appWeb.use(cookieParser('keyboard cat'));
    appWeb.use(
        session({
            cookie: { maxAge: 300000 },
            store: new FileStore(fileStoreOptions),
            secret: 'keyboard cat',
            resave: true,
            saveUninitialized: true,
            unset: 'destroy',
        }),
    );
    appRest.use(
        session({
            cookie: { maxAge: 300000 },
            store: new FileStore(fileStoreOptions),
            secret: 'keyboard cat',
            resave: true,
            saveUninitialized: true,
            unset: 'destroy',
        }),
    );

    // Set up rate limiting
    if (globals.config.has('ButlerAuth.server.rest.rateLimit.enable') && globals.config.get('ButlerAuth.server.rest.rateLimit.enable')) {
        appRest.use(rateLimit.limiterRest);
    }

    // --------------------------------------------
    // Set up file authentication endpoint
    if (globals.config.has('ButlerAuth.authProvider.localFile.enable') && globals.config.get('ButlerAuth.authProvider.localFile.enable')) {
        authLocalFile.registerAuthEndpoint(passport, appRest, appWeb);
    }

    // --------------------------------------------
    // Set up ldapauth authentication endpoint
    if (globals.config.has('ButlerAuth.authProvider.ldap.enable') && globals.config.get('ButlerAuth.authProvider.ldap.enable')) {
        authLdapAuth.registerAuthEndpoint(passport, appRest, appWeb);
    }

    // --------------------------------------------
    // Set up Google authentication endpoint
    if (globals.config.has('ButlerAuth.authProvider.google.enable') && globals.config.get('ButlerAuth.authProvider.google.enable')) {
        authGoogle.registerAuthEndpoint(passport, appRest);
    }

    // --------------------------------------------
    // Set up Facebook authentication endpoint
    if (globals.config.has('ButlerAuth.authProvider.facebook.enable') && globals.config.get('ButlerAuth.authProvider.facebook.enable')) {
        authFacebook.registerAuthEndpoint(passport, appRest);
    }

    // --------------------------------------------
    // Set up Microsoft authentication endpoint
    if (globals.config.has('ButlerAuth.authProvider.microsoft.enable') && globals.config.get('ButlerAuth.authProvider.microsoft.enable')) {
        authMicrosoft.registerAuthEndpoint(passport, appRest);
    }

    // --------------------------------------------
    // Set up Okta authentication endpoint
    if (globals.config.has('ButlerAuth.authProvider.okta.enable') && globals.config.get('ButlerAuth.authProvider.okta.enable')) {
        authOkta.registerAuthEndpoint(passport, appRest);
    }

    // --------------------------------------------
    // Set up Keycloak authentication endpoint
    if (globals.config.has('ButlerAuth.authProvider.keycloak.enable') && globals.config.get('ButlerAuth.authProvider.keycloak.enable')) {
        authKeycloak.registerAuthEndpoint(passport, appRest);
    }

    // --------------------------------------------
    // Set up Auth0 authentication endpoint
    if (globals.config.has('ButlerAuth.authProvider.auth0.enable') && globals.config.get('ButlerAuth.authProvider.auth0.enable')) {
        authAuth0.registerAuthEndpoint(passport, appRest);
    }

    // --------------------------------------------
    // Set up single user authentication endpoint
    if (globals.config.has('ButlerAuth.authProvider.singleUser.enable') && globals.config.get('ButlerAuth.authProvider.singleUser.enable')) {
        authSingleUser.registerAuthEndpoint(appRest);
    }

    // Set up heartbeats, if enabled in the config file
    if (globals.config.has('ButlerAuth.heartbeat.enable') && globals.config.get('ButlerAuth.heartbeat.enable')) {
        heartbeat.setupHeartbeatTimer(globals.config, globals.logger);
    }

    // Set specific log level (if/when needed to override the config file setting)
    // Possible values are { error: 0, warn: 1, info: 2, verbose: 3, debug: 4, silly: 5 }
    // Default is to use log level defined in config file
    globals.logger.info('--------------------------------------');
    globals.logger.info('Starting Butler authenticator');
    globals.logger.info(`Log level: ${globals.getLoggingLevel()}`);
    globals.logger.info(`App version: ${globals.appVersion}`);
    globals.logger.info('--------------------------------------');

    // Start REST server
    let serverRest = '';
    if (globals.config.has('ButlerAuth.server.rest.tls.enable') && globals.config.get('ButlerAuth.server.rest.tls.enable')) {
        serverRest = https.createServer(
            {
                key: fs.readFileSync(globals.config.get('ButlerAuth.server.rest.tls.key')),
                cert: fs.readFileSync(globals.config.get('ButlerAuth.server.rest.tls.cert')),
                passphrase: globals.config.get('ButlerAuth.server.rest.tls.password'),
            },
            appRest,
        );
    } else {
        serverRest = http.createServer(appRest);
    }

    serverRest.listen(
        globals.config.get('ButlerAuth.server.rest.port'),
        globals.config.get('ButlerAuth.server.rest.host'),
        function () {
            globals.logger.info(
                `MAIN: REST server now listening on ${globals.config.get(
                    'ButlerAuth.server.rest.host',
                )}:${globals.config.get('ButlerAuth.server.rest.port')}`,
            );
        },
    );

    // Start web server
    let serverWeb = '';
    if (globals.config.has('ButlerAuth.server.web.tls.enable') && globals.config.get('ButlerAuth.server.web.tls.enable')) {
        serverWeb = https.createServer(
            {
                key: fs.readFileSync(globals.config.get('ButlerAuth.server.web.tls.key')),
                cert: fs.readFileSync(globals.config.get('ButlerAuth.server.web.tls.cert')),
                passphrase: globals.config.get('ButlerAuth.server.web.tls.password'),
            },
            appWeb,
        );
    } else {
        serverWeb = http.createServer(appWeb);
    }

    serverWeb.listen(
        globals.config.get('ButlerAuth.server.web.port'),
        globals.config.get('ButlerAuth.server.web.host'),
        function () {
            globals.logger.info(
                `MAIN: Web server now listening on ${globals.config.get(
                    'ButlerAuth.server.web.host',
                )}:${globals.config.get('ButlerAuth.server.web.port')}`,
            );
        },
    );
}

main().catch(console.error);

String.prototype.endsWith = function (suffix) {
    return this.indexOf(suffix, this.length - suffix.length) !== -1;
};
