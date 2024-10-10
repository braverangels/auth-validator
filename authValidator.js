// authValidator.js
const jwt = require('jsonwebtoken');
const jwksClient = require('jwks-rsa');

let config = {
    audience: '',
    issuer: '',
    authMode: 'OPTIONAL',
    apiKey: '',
    jwksUri: ''
};

// Function to configure environment variables
function configure(options) {
    config = { ...config, ...options };
}

// Set up the JWKS client to fetch the public key from Auth0
const client = jwksClient({
    jwksUri: config.jwksUri
});

// Function to retrieve signing key from Auth0
function getKey(header, callback) {
    client.getSigningKey(header.kid, function (err, key) {
        if (err) {
            callback(err);
        } else {
            const signingKey = key.getPublicKey();
            callback(null, signingKey);
        }
    });
}

// Function to verify JWT or API Key
async function verifyTokenAndRespond(req) {
    const env = process.env;
    const authHeader = req.headers.authorization;
    const apiKey = req.headers['ba_api_key'];
    const isAuthModeRequired = config.authMode === 'REQUIRED';

    if (apiKey && apiKey === env.BA_API_KEY) {
        return true; // Valid API Key
    }

    // Check if AUTHMODE is REQUIRED or if Authorization header is present
    if (isAuthModeRequired || (authHeader && authHeader.startsWith('Bearer '))) {
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return false; // Missing or invalid authorization
        }

        const token = authHeader.split(' ')[1]; // Extract the JWT token


        try {
            const decoded = await new Promise((resolve, reject) => {
                jwt.verify(token, getKey, {
                    audience: config.audience,
                    issuer: config.issuer
                }, (err, decoded) => {
                    if (err) {
                        reject(err);
                    } else {
                        resolve(decoded);
                    }
                });
            });

            // Token is valid
            return true;

        } catch (err) {
            return false; // Invalid token
        }
    }

    // If AUTHMODE is not REQUIRED and no valid authorization is provided
    return false;
}

module.exports = { configure, verifyTokenAndRespond };
