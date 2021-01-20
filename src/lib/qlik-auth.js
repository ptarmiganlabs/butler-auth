var url = require('url');
var fs = require('fs');
var https = require('https');
var crypto = require('crypto');
// var urljoin = require('url-join');
// var _ = require('underscore');
var config = require('config');
const axios = require('axios');
const globals = require('./globals');

// function getFileRealPath(s) {
//     try {
//         return fs.realpathSync(s);
//     } catch (e) {
//         return null;
//     }
// }


// TODO Verify this module doesn't leak memory
// TODO Error scenarios
// TODO Validation of input parameters

class QlikAuth {
    constructor(proxyRestUri, targetId) {
        // if (!options) var options = {};
        this.options = {};

        // Store targetId and proxyRestUri for later use (needed when calling Sense again, after successful auth)
        if (proxyRestUri != undefined && targetId != undefined) {
            this.qlikAuthSession = {
                targetId: targetId,
                proxyRestUri: proxyRestUri,
            };
        }

        // if (url.parse(req.url, true).query.targetId != undefined) {
        //     this.qlikAuthSession = {
        //         targetId: url.parse(req.url, true).query.targetId,
        //         proxyRestUri: url.parse(req.url, true).query.proxyRestUri,
        //     };
        // }

        // Load Sense certificates in constructor, to avoid disk access each time a user logs on.
        this.getCertificates();
    }

    getCertificates() {
        let certificateFile = config.get('ButlerAuth.qlikSense.certFile.clientCert'),
            certificateKeyFile = config.get('ButlerAuth.qlikSense.certFile.clientCertKey'),
            certificateCAFile = config.get('ButlerAuth.qlikSense.certFile.clientCertCA');

        this.options.certificateFilePassphrase = config.get('ButlerAuth.qlikSense.certFile.clientCertPassphrase');

        this.options.certificate = {};

        try {
            this.options.certificate.cert = fs.readFileSync(certificateFile);
            this.options.certificate.key = fs.readFileSync(certificateKeyFile);
            this.options.certificate.ca = fs.readFileSync(certificateCAFile);
        } catch (err) {
            globals.logger.error('Failed loading certificate file(s) from disk.');
        }
    }

    generateXrfkey(size, chars) {
        size = size || 16;
        chars = chars || 'abcdefghijklmnopqrstuwxyzABCDEFGHIJKLMNOPQRSTUWXYZ0123456789';

        var rnd = crypto.randomBytes(size),
            value = new Array(size),
            len = chars.length;

        for (var i = 0; i < size; i++) {
            value[i] = chars[rnd[i] % len];
        }

        return value.join('');
    }

    // requestTicket: function(req, res, profile, options) {
    async requestTicket(req, res, profile) {
        try {
            // Get and verify parameters

            // options.Certificate = options.Certificate || 'client.pem';
            // options.CertificateKey = options.CertificateKey || 'client_key.pem';
            // options.PassPhrase = options.PassPhrase || '';
            // options.proxyRestUri = options.proxyRestUri || url.parse(req.url, true).query.proxyRestUri;
            // options.targetId = options.targetId || url.parse(req.url, true).query.targetId;

            // TODO
            this.options.proxyRestUri =
                this.qlikAuthSession.proxyRestUri || url.parse(req.url, true).query.proxyRestUri;
            this.options.targetId = this.qlikAuthSession.targetId;

            // options.proxyRestUri = url.parse(req.url, true).query.proxyRestUri;
            // options.targetId = url.parse(req.url, true).query.targetId;

            // if (this.qlikAuthSession) {
            //     this.options.proxyRestUri = this.qlikAuthSession.proxyRestUri;
            //     this.options.targetId = this.qlikAuthSession.targetId;
            // }

            // Deal with missing mandatory parameters
            if (!this.options.proxyRestUri) {
                res.end('Missing "proxyRestUri" parameter when requesting ticket from Qlik Sense');
                return;
            }
            if (!this.options.targetId) {
                res.end('Missing "targetId" parameter when requesting ticket from Qlik Sense');
                return;
            }
            if (!profile.userId) {
                res.end('Missing "userId" when retrieving Qlik Sense ticket');
                return;
            }

            // Get certificates used to authenticate with Sense proxy service
            // var cert = getCertificates(this.options);

            if (
                this.options.certificate.cert === undefined ||
                this.options.certificate.key === undefined ||
                this.options.certificate.ca === undefined
            ) {
                res.end('Client certificate or key was not found');
                return;
            }

            const httpsAgent = new https.Agent({
                cert: this.options.certificate.cert,
                key: this.options.certificate.key,
                ca: this.options.certificate.ca,
                passphrase: this.options.certificateFilePassphrase,
                rejectUnauthorized: false,
            });

            // Configure parameters for the ticket request
            var xrfkey = this.generateXrfkey();
            var settings = {
                method: 'post',
                // url: urljoin(url.parse(options.proxyRestUri).path, 'ticket?xrfkey=' + xrfkey),
                // host: url.parse(options.proxyRestUri).hostname,
                // port: url.parse(options.proxyRestUri).port,
                headers: {
                    'X-Qlik-Xrfkey': xrfkey,
                    'Content-Type': 'application/json',
                },
                // agent: false,
                httpsAgent: httpsAgent,
                data: {
                    UserDirectory: profile.userDirectory,
                    UserId: profile.userId,
                    Attributes: profile.attributes || [],
                    TargetId: this.options.targetId.toString(),
                },
            };

            // settings = _.extend(settings, cert);
        } catch (err) {
            globals.logger.error(`QLIKAUTH: Error setting up call to Sense: ${err}`);
        }

        // Send ticket request
        const requestUrl = this.options.proxyRestUri + 'ticket?xrfkey=' + xrfkey;
        var ticket;

        try {
            var response = await axios.request(requestUrl, settings);
            ticket = response.data;
        } catch (err) {
            globals.logger.error(`QLIKAUTH: Error when requesting Qlik access token: ${err}`);
        }

        try {
            // Build redirect including ticket
            let redirectURI = '';
            if (ticket.TargetUri.indexOf('?') > 0) {
                redirectURI = ticket.TargetUri + '&QlikTicket=' + ticket.Ticket;
            } else {
                redirectURI = ticket.TargetUri + '?QlikTicket=' + ticket.Ticket;
            }

            res.writeHead(302, {
                Location: redirectURI,
            });
            res.end();
        } catch (err) {
            res.end();
            globals.logger.error(`QLIKAUTH: Error after getting ticket from Sense: ${err}`);
        }
    }
}

module.exports = {
    QlikAuth,
};
