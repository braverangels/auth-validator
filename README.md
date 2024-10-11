# Auth Validator Module

This Node.js module provides utilities for handling authentication using either API keys or JWTs (JSON Web Tokens). It integrates with Auth0 for JWT verification and allows configuration of authentication modes.

## Table of Contents

- [Installation](#installation)
- [Configuration](#configuration)
- [Functions](#functions)
    - [configure](#configureoptions)
    - [addBAAuthHeader](#addbaauthheaderfetchoptions-opttoken)
    - [verifyTokenAndRespond](#verifytokenandrespondreq)
- [Usage Example](#usage-example)

## Installation

To use this module in your project, ensure you have the required dependencies:

```bash
npm install jsonwebtoken jwks-rsa

Here is the content you provided converted to proper Markdown format:

```markdown
# Auth Validator Module

This Node.js module provides utilities for handling authentication using either API keys or JWTs (JSON Web Tokens). It integrates with Auth0 for JWT verification and allows configuration of authentication modes.

## Installation

To include the module in your project:

```js
const authValidator = require('./authValidator');
```

Here is the full response in markdown:

```markdown
# Auth Validator Module

This Node.js module provides utilities for handling authentication using either API keys or JWTs (JSON Web Tokens). It integrates with Auth0 for JWT verification and allows configuration of authentication modes.

## Table of Contents

- [Installation](#installation)
- [Configuration](#configuration)
- [Functions](#functions)
  - [configure](#configureoptions)
  - [addBAAuthHeader](#addbaauthheaderfetchoptions-opttoken)
  - [verifyTokenAndRespond](#verifytokenandrespondreq)
- [Usage Example](#usage-example)

## Installation

To use this module in your project, ensure you have the required dependencies:

```bash
npm install jsonwebtoken jwks-rsa
```

Then, include the module in your project:

```js
const authValidator = require('./authValidator');
```

## Configuration

Before using the authentication utilities, you need to configure the module with appropriate settings such as API keys, audience, issuer, and Auth0 JWKS URI.

### Available Configuration Options

- `apiKey`: The API key for validating requests (optional).
- `audience`: The expected audience for JWT validation.
- `issuer`: The expected issuer for JWT validation.
- `authMode`: The authentication mode. Valid values are:
    - `NONE`: No authentication required.
    - `OPTIONAL`: Authentication is optional, but if a token is provided, it will be validated.
    - `REQUIRED`: A valid token or API key is required.
- `jwksUri`: The URI for the JSON Web Key Set (JWKS) to verify JWT signatures.

### Example Configuration

```js
authValidator.configure({
    apiKey: 'your-api-key',
    audience: 'your-auth0-audience',
    issuer: 'your-auth0-issuer',
    authMode: 'REQUIRED',
    jwksUri: 'https://your-auth0-domain/.well-known/jwks.json'
});
```

## Functions

### `configure(options)`

This function allows you to configure the module with your specific settings.

#### Parameters

- `options` - An object containing the following properties:
    - `apiKey` (optional): API key for request validation.
    - `audience` (required for JWT validation): Expected audience for JWT validation.
    - `issuer` (required for JWT validation): Expected issuer for JWT validation.
    - `authMode` (optional): Authentication mode. Can be 'NONE', 'OPTIONAL', or 'REQUIRED'.
    - `jwksUri` (required for JWT validation): URI to fetch the JSON Web Key Set (JWKS).

#### Example

```js
authValidator.configure({
    apiKey: 'your-api-key',
    audience: 'your-auth0-audience',
    issuer: 'your-auth0-issuer',
    authMode: 'OPTIONAL',
    jwksUri: 'https://your-auth0-domain/.well-known/jwks.json'
});
```

### `addBAAuthHeader(fetchOptions, [optToken])`

This function adds a Bearer Authorization header to the provided fetch options. By default, it uses the API key, but you can provide an optional token.

#### Parameters

- `fetchOptions` - An object containing options for a fetch request, including headers.
- `optToken` (optional) - A token to use instead of the API key.

#### Returns

The updated `fetchOptions` object with the Authorization header added.

#### Example

```js
let fetchOptions = { headers: {} };
fetchOptions = authValidator.addBAAuthHeader(fetchOptions, 'optional-bearer-token');
```

### `verifyTokenAndRespond(req)`

This function verifies the JWT or API key provided in the request headers. It checks the headers for a Bearer token or custom API key and validates based on the configured `authMode`.

#### Parameters

- `req` - The Express `req` object containing headers. It should include:
    - `authorization` (optional): The Bearer token in the `Authorization` header.
    - `ba_api_key` (optional): A custom header for API key validation.

#### Returns

A `Promise<boolean>` that resolves to `true` if the request is authenticated or `false` if it is not.

#### Example

```js
app.get('/protected-endpoint', async (req, res) => {
    const isAuthenticated = await authValidator.verifyTokenAndRespond(req);
    if (isAuthenticated) {
        res.status(200).send('Authorized!');
    } else {
        res.status(401).send('Unauthorized!');
    }
});
```

## Usage Example

Here is a simple example of how to configure and use this module in an Express application:

```js
const express = require('express');
const authValidator = require('auth-validator');

const app = express();

// Configure the auth validator
authValidator.configure({
    apiKey: 'your-api-key',
    audience: 'your-auth0-audience',
    issuer: 'your-auth0-issuer',
    authMode: 'REQUIRED',
    jwksUri: 'https://your-auth0-domain/.well-known/jwks.json'
});

app.use(express.json());

// Example protected route
app.get('/api/protected', async (req, res) => {
    const isAuthenticated = await authValidator.verifyTokenAndRespond(req);
    if (isAuthenticated) {
        res.status(200).send('You have access to this protected route!');
    } else {
        res.status(401).send('Unauthorized access.');
    }
});

// Start the server
app.listen(3000, () => {
    console.log('Server running on port 3000');
});
```

## License

This module is available under the MIT License.
```

This `README.md` file provides an overview of the module, describes its configuration, and explains how to use each function. It also includes a usage example to demonstrate how to integrate the module into an Express app.
