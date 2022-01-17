# Collective Benefits Tech Assessment

Our platform is comprised of a set of single-page web applications interacting with backend microservices through REST APIs.
We use AWS Cognito for authentication and authorisation, which follows the OAuth 2.0 standard.
Users authenticate with AWS Cognito and the web applications ultimately receive an access token in the form of a JWT to authorise the user to access our backend APIs.
The `sub` claim contained in the encoded and digitally signed access token identifies the user intending to access the API.

In this exercise, you will create a Node.js Express middleware package to be consumed by our microservices to validate the access token and read out the user ID.
The middleware should meet the following acceptance criteria:

* For a valid token, it should add a `user` field to the request object containing all claims, and then delegate to the next middleware.
* For an invalid token, it should end the request-response cycle by returning a 401 response.
* It should confirm the structure of the JWT, validate the JWT signature, and verify the claims, as described in this article: https://docs.aws.amazon.com/cognito/latest/developerguide/amazon-cognito-user-pools-using-tokens-verifying-a-jwt.html.

We intend to use the `verify` function of the `jsonwebtoken` NPM package to do much of the heavy-lifting (https://www.npmjs.com/package/jsonwebtoken#jwtverifytoken-secretorpublickey-options-callback).

HINT: you might be best using the alternative `decode` function provided by `jsonwebtoken` to get started (https://www.npmjs.com/package/jsonwebtoken#jwtdecodetoken--options).

A failing "happy path" test has already been set up for you, including a mock response for the request to retrieve the public key used to verify the token signature.

# Explanation

```JwtAuthenticator``` (found in ```src/middlewear/auth/index.js```) exposes the method ```authenticateToken()```. This leverages the ```jsonwebtoken``` package to check the tokens: 1) header, 2) payload, 3) signature. When a token is valid the method calls ```next()``` (directing to the next piece of middleware or controller) and adds the decodedToken to the ```req``` object. When a token is invalid it returns either a 401 or 500 status code (custom error classes can be easily added to ```src/middlewear/auth/error.js```).

To validate the process described above works for invalid users, two new tests have been added to the test suite. The existing test has been extended to assert ```next()``` is called for a valid token.

Eslint was added with basic rules to make the new and existing code consistent.

