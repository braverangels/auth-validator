/**
 * @module auth-validator
 */

// Git version update instructions
// After commit: npm version patch
// Then do git push origin main --tags

const jwt = require('jsonwebtoken');
const jwksClient = require('jwks-rsa');

let config = {
    apiKey: '',
    audience: '',
    issuer: '',
    authMode: 'NONE',
    jwksUri: '',
    debugMode: false // Enable or disable debug logging
};

/**
 * Configure the authentication settings.
 * @param {Object} options - Configuration options.
 * @param {string} [options.apiKey] - API key for the application.
 * @param {string} [options.audience] - Expected audience for JWT verification.
 * @param {string} [options.issuer] - Expected issuer for JWT verification.
 * @param {string} [options.authMode] - Authentication mode ('NONE', 'OPTIONAL', or 'REQUIRED').
 * @param {string} [options.jwksUri] - URI to retrieve JSON Web Key Set (JWKS).
 * @param {boolean} [options.debugMode] - Enable debug logging.
 */
function configure(options) {
    config = { ...config, ...options };
    if (config.debugMode) {
        console.log('Configuration updated:', JSON.stringify(config));
    }
    for (let key in config) {
        if (config[key] === undefined) {
            console.error("Missing OAuth config parameter: " + key);
        }
    }
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
    fetchOptions.headers = fetchOptions.headers || {};

    if (optBearerToken) {
        fetchOptions.headers['Authorization'] = `Bearer ${optBearerToken}`;
    } else {
        fetchOptions.headers['BA_API_KEY'] = `${config.apiKey}`;
    }

    if (config.debugMode) {
        console.log('Updated fetch options with headers:', JSON.stringify(fetchOptions.headers));
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
            if (config.debugMode) {
                console.error('Error retrieving signing key:', err);
            }
            callback(err);
        } else {
            const signingKey = key.getPublicKey();
            if (config.debugMode) {
                console.log('Retrieved signing key:', signingKey);
            }
            callback(null, signingKey);
        }
    });
}

/**
 * Verify the JWT or API key and determine if the request is authenticated.
 * It checks the headers for a Bearer token or API key and validates based on the configured authMode.
 * @param {Object} req - Express request object.
 * @param {Object} req.headers - Headers from the request.
 * @returns {Promise<boolean>} A promise that resolves to `true` if the token or API key is valid, otherwise `false`.
 */
async function verifyTokenAndRespond(req) {
    const authHeader = req.headers.authorization;
    const apiKey = req.headers['ba_api_key'];
    const authMode = config.authMode;
    const hasBearerTokenHeader = authHeader && authHeader.startsWith('Bearer ');

    const requestOrigin = {
        ip: req.ip || req.connection.remoteAddress,
        userAgent: req.headers['user-agent'] || 'Unknown'
    };

    if (config.debugMode) {
        console.log('Request origin:', JSON.stringify(requestOrigin));
        console.log('Request headers:', JSON.stringify(req.headers));
        console.log('Auth mode:', authMode);
    }

    if (authMode === 'NONE') {
        if (config.debugMode) {
            console.log('Auth mode is NONE. Skipping authentication.', JSON.stringify(requestOrigin));
        }
        return true;
    }

    if (authMode === 'OPTIONAL' && !hasBearerTokenHeader && !apiKey) {
        if (config.debugMode) {
            console.log('Auth mode is OPTIONAL. No API key or Bearer token provided.', JSON.stringify(requestOrigin));
        }
        return true;
    }

    if (apiKey && apiKey === config.apiKey) {
        if (config.debugMode) {
            console.log('Valid API key provided.', JSON.stringify(requestOrigin));
        }
        return true;
    }

    if (authMode === 'REQUIRED' && !hasBearerTokenHeader && !apiKey) {
        if (config.debugMode) {
            console.error('Auth mode is REQUIRED. Missing API key or Bearer token.', JSON.stringify(requestOrigin));
        }
        return false;
    }

    if (authMode !== 'NONE' && apiKey && apiKey !== config.apiKey) {
        if (config.debugMode) {
            console.error('Invalid API key provided:', apiKey, JSON.stringify(requestOrigin));
        }
        return false;
    }

    if ((authMode === 'OPTIONAL' || authMode === 'REQUIRED') && hasBearerTokenHeader) {
        const token = authHeader.split(' ')[1];

        try {
            const decoded = await new Promise((resolve, reject) => {
                jwt.verify(token, getKey, {
                    audience: config.audience,
                    issuer: config.issuer
                }, (err, decoded) => {
                    if (err) {
                        if (config.debugMode) {
                            console.error('JWT verification error:', err, JSON.stringify(requestOrigin));
                        }
                        reject(err);
                    } else {
                        resolve(decoded);
                    }
                });
            });

            if (config.debugMode) {
                console.log('JWT successfully verified. Decoded token:', JSON.stringify(decoded), JSON.stringify(requestOrigin));
            }

            return true;
        } catch (err) {
            if (config.debugMode) {
                console.error('Invalid JWT:', JSON.stringify(err), JSON.stringify(requestOrigin));
            }
            return false;
        }
    }

    if (config.debugMode) {
        console.error('No valid authorization provided.', JSON.stringify(requestOrigin));
    }

    return false;
}


module.exports = { configure, addBAAuthHeader, verifyTokenAndRespond };
