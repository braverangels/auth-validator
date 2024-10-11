// authValidator.js
const jwt = require('jsonwebtoken');
const jwksClient = require('jwks-rsa');

let config = {
    apiKey: '',
    audience: '',
    issuer: '',
    authMode: 'OPTIONAL',
    jwksUri: ''
};

// Function to configure environment variables
function configure(options) {
    config = { ...config, ...options };
}

// Function to add an auth token to the options variable for a fetch request
// Default behavior is to add the BA API Key, but can also be used to add any bearer token
function addAuthHeader(fetchOptions, optToken) {
    let token = optToken ? optToken : config.apiKey;
    fetchOptions.headers['Authorization'] = `Bearer ${token}`;
    return fetchOptions;
}

// Function to retrieve signing key from Auth0
function getKey(header, callback) {
    // Set up the JWKS client to fetch the public key from Auth0
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

// Function to verify JWT or API Key
async function verifyTokenAndRespond(req) {
    console.log(JSON.stringify(config));
    const authHeader = req.headers.authorization;
    const apiKey = req.headers['ba_api_key'];
    const isAuthModeRequired = config.authMode === 'REQUIRED';
    console.log('isAuthModeRequired: ' + isAuthModeRequired);

    if (apiKey && apiKey === config.apiKey) {
        return true; // Valid API Key
    }

    const hasBearerTokenHeader = authHeader && authHeader.startsWith('Bearer ');

    //Auth is not required AND no bearer token is included in the request
    if (!isAuthModeRequired && !hasBearerTokenHeader) {
        return true;
    }

    //Auth is required AND no bearer token is included in the request
    if (isAuthModeRequired && !hasBearerTokenHeader) {
        return false;
    }

    //The request has a bearer token
    if (hasBearerTokenHeader) {

        const token = authHeader.split(' ')[1]; // Extract the JWT token

        try {
            const decoded = await new Promise((resolve, reject) => {
                jwt.verify(token, getKey, {
                    audience: config.audience,
                    issuer: config.issuer
                }, (err, decoded) => {
                    if (err) {
                        console.log("Error decoding key: " + JSON.stringify(err));
                        reject(err);
                    } else {
                        resolve(decoded);
                    }
                });
            });

            // Token is valid
            return true;

        } catch (err) {
            console.log(err);
            return false; // Invalid token
        }
    }

    // If AUTHMODE is not REQUIRED and no valid authorization is provided
    return false;
}

module.exports = { configure, addAuthHeader, verifyTokenAndRespond };
