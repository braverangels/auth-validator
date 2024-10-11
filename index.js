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
function addBAAuthHeader(fetchOptions, optToken) {
    let token = optToken ? optToken : config.apiKey;
    fetchOptions.headers['Authorization'] = `Bearer ${token}`;
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
    console.log(JSON.stringify(config));
    const authHeader = req.headers.authorization;
    const apiKey = req.headers['ba_api_key'];
    const authMode = config.authMode;

    if (authMode === 'NONE') {
        return true;
    }

    if (apiKey && apiKey === config.apiKey) {
        return true; // Valid API Key
    }

    const hasBearerTokenHeader = authHeader && authHeader.startsWith('Bearer ');

    if (authMode === 'OPTIONAL' && !hasBearerTokenHeader) {
        return true;
    }

    if (authMode === 'REQUIRED' && !hasBearerTokenHeader) {
        return false;
    }

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
