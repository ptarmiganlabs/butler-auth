const rateLimit = require('express-rate-limit');
const globals = require('./globals');

// What should be done when rate limit is reached
// const limitReachedRest = (req: express.Request, res: express.Response, options) => {
const limitReachedRest = (req, res, options) => {
    globals.logger.warn(`Rate limiter triggered for IP ${req.ip}`);

    // res.status(429).send('Too many login requests for Qlik Sense. Try again later.');
    // res.send('Too many login requests for Qlik Sense. Try again later.');
    // renderError(req, res); // Your function to render an error page
};

const handlerRest = (req, res, next) => {
    globals.logger.warn(
        `Rate limiter triggered for IP ${req.ip}. Attempt ${req.rateLimit.current}, limit is ${req.rateLimit.limit}`,
    );

    res.status(optionsRest.statusCode).send(optionsRest.message);

    // res.status(429).send('Too many login requests for Qlik Sense. Try again later.');
    // res.send('Too many login requests for Qlik Sense. Try again later.');
    // renderError(req, res); // Your function to render an error page
};

var optionsRest = {
    windowMs: globals.config.has('ButlerAuth.server.rest.rateLimit.windowSize')
        ? globals.config.get('ButlerAuth.server.rest.rateLimit.windowSize')
        : 300000,
    max: globals.config.has('ButlerAuth.server.rest.rateLimit.maxCalls')
        ? globals.config.get('ButlerAuth.server.rest.rateLimit.maxCalls')
        : 100,
    statusCode: 429,
    message: 'Too many login requests for Qlik Sense. Try again later.',
    headers: false,
    draft_polli_ratelimit_headers: false,
};

// Set up REST API rate limiting
const limiterRest = rateLimit({
    optionsRest,
    onLimitReached: limitReachedRest, // called once when max is reached
    handler: handlerRest, // called for each subsequent request once
});

module.exports = {
    limiterRest,
};
