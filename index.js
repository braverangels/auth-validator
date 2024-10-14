/**
 * @module auth-validator
 */

const jwt = require('jsonwebtoken');
const jwksClient = require('jwks-rsa');

let config = {
    apiKey: '',
    audience: '',
    issuer: '',
    authMode: 'NONE',
    jwksUri: ''
};

/**
 * Configure the authentication settings.
 * @param {Object} options - Configuration options.
 * @param {string} [options.apiKey] - API key for the application.
 * @param {string} [options.audience] - Expected audience for JWT verification.
 * @param {string} [options.issuer] - Expected issuer for JWT verification.
 * @param {string} [options.authMode] - Authentication mode ('NONE', 'OPTIONAL', or 'REQUIRED').
 * @param {string} [options.jwksUri] - URI to retrieve JSON Web Key Set (JWKS).
 */
function configure(options) {
    config = { ...config, ...options };
}

/**
 * Add a Bearer Authorization header to the fetch options.
 * By default, it uses the API key, but an optional token can be provided.
 * @param {Object} fetchOptions - Options object for fetch request.
 * @param {Object} fetchOptions.headers - Headers object for the fetch request.
 * @param {string} [optToken] - Optional token to override the API key.
 * @returns {Object} Updated fetch options with the Authorization header.
 */
function addBAAuthHeader(fetchOptions, optBearerToken) {

    fetchOptions.headers = fetchOptions.headers ? fetchOptions.headers : {};

    if (optBearerToken) {
        fetchOptions.headers['Authorization'] = `Bearer ${token}`;
    } else {
        fetchOptions.headers['BA_API_KEY'] = `${config.apiKey}`;
    }

    return fetchOptions;
}

/**
 * Retrieve the signing key from Auth0 to verify the JWT signature.
 * @param {Object} header - JWT header containing the 'kid' (key ID).
 * @param {function} callback - Callback function that takes error and signing key.
 */
function getKey(header, callback) {
    const client = jwksClient({
        jwksUri: config.jwksUri
    });

    client.getSigningKey(header.kid, function (err, key) {
        if (err) {
            console.log("Error getting signing key: " + JSON.stringify(err));
            callback(err);
        } else {
            const signingKey = key.getPublicKey();
            callback(null, signingKey);
        }
    });
}

/**
 * Verify the JWT or API key and determine if the request is authenticated.
 * It checks the headers for a Bearer token or API key and validates based on the configured authMode.
 * @param {Object} req - Express request object.
 * @param {Object} req.headers - Headers from the request.
 * @param {string} [req.headers.authorization] - Authorization header containing the Bearer token.
 * @param {string} [req.headers['ba_api_key']] - Custom header for the BA API key.
 * @returns {Promise<boolean>} A promise that resolves to `true` if the token or API key is valid, otherwise `false`.
 */
async function verifyTokenAndRespond(req) {

    const authHeader = req.headers.authorization;
    const apiKey = req.headers['ba_api_key'];
    const authMode = config.authMode;
    const hasBearerTokenHeader = authHeader && authHeader.startsWith('Bearer ');
    console.log(JSON.stringify(config));
    console.log(JSON.stringify(req.headers));

    //No auth needed
    if (authMode === 'NONE') {
        return true;
    }

    //Auth mode optional, no bearer token or API KEY is provided.
    if (authMode === 'OPTIONAL' && !hasBearerTokenHeader && !apiKey) {
        return true;
    }

    //Any auth mode where a valid api key is provided
    if (apiKey && apiKey === config.apiKey) {
        return true; // Valid API Key
    }

    //When auth is required, reject any calls with both no bearer token and no api key
    if (authMode === 'REQUIRED' && !hasBearerTokenHeader && !apiKey) {
        return false;
    }

    //When an invalid API Key is provided.  Reject unless auth mode is set to NONE.
    if (authMode !== 'NONE' && apiKey && apiKey !== config.apiKey) {
        console.error('Invalid API key value provided: ' + apiKey);
        return false;
    }

    //Bearer token is included, authmode is either optional or required
    if ((authMode === "OPTIONAL" || authMode === "REQUIRED") && hasBearerTokenHeader) {
        const token = authHeader.split(' ')[1]; // Extract the JWT token

        try {
            const decoded = await new Promise((resolve, reject) => {
                jwt.verify(token, getKey, {
                    audience: config.audience,
                    issuer: config.issuer
                }, (err, decoded) => {
                    if (err) {
                        console.error("Error decoding key: " + JSON.stringify(err));
                        reject(err);
                    } else {
                        resolve(decoded);
                    }
                });
            });

            return true; // Token is valid
        } catch (err) {
            console.error(err);
            return false; // Invalid token
        }
    }

    return false; // No valid authorization provided
}

module.exports = { configure, addBAAuthHeader, verifyTokenAndRespond };
