import axios from "axios";
import jwt from "jsonwebtoken";
import jwkToPem from "jwk-to-pem";
import AuthenticationError from "./error";

export default class JwtAuthenticator {
  ERROR_MESSAGES = {
    NO_TOKEN: "no jwt provided.",
    INVALID_TOKEN_USE_CLAIM: "jwt token_use invalid.",
    INVALID_PAYLOAD: "jwt payload or header invalid.",
    GENERAL_ERROR: "server error.",
    NO_JWK: "no jwk found.",
  };

  constructor() {
    this.USER_POOL = "http://issuer.com"; // mock value for verifying claims real value may look like https://cognito-idp.us-east-1.amazonaws.com/<userpoolID>
    this.APP_CLIENT_ID = "audience"; // mock value for verifying claims real value may look like the app client ID that was created in the Amazon Cognito user pool.
    this.SUBJECT = "foo";
    this.TOKEN_USE = "access";
  }

  async #fetchKeys() {
    const { data: { keys } } = await axios.get(`${this.USER_POOL}/.well-known/jwks.json`);
    return keys;
  }

  #isTokenUseClaimValid({ token_use: tokenUse }) {
    return tokenUse === this.TOKEN_USE;
  }

  // stops sensitive data such as APP_CLIENT_ID being exposed.
  #formatClaimErrorMessage(message) {
    return message.replace(/\sexpected:\s.*/i, "");
  }

  #verifySignature(token, pem, options) {
    return new Promise((resolve, reject) => {
      jwt.verify(token, pem, options, (err, decodedToken) => {
        if (err) {
          return reject(new AuthenticationError(this.#formatClaimErrorMessage(err.message)));
        };
 
        if (!this.#isTokenUseClaimValid(decodedToken)) {
          return reject(new AuthenticationError(this.ERROR_MESSAGES.INVALID_TOKEN_USE_CLAIM));
        };

        resolve(decodedToken);
      });
    });
  }

  async #decodeToken(token) {
    if (!token) throw new AuthenticationError(this.ERROR_MESSAGES.NO_TOKEN);
    
    const decodedToken = jwt.decode(token, { complete: true });
    if (!decodedToken) throw new AuthenticationError(this.ERROR_MESSAGES.INVALID_PAYLOAD);
    
    const { header: { kid, alg }, payload } = decodedToken;
    
    const keys = await this.#fetchKeys();
    const key = keys.find(({ kid: keyId }) => kid === keyId);
    if (!key) throw new AuthenticationError(this.ERROR_MESSAGES.NO_JWK);

    const pem = jwkToPem(key);

    const options = {
      algorithms: [alg],
      issuer: this.USER_POOL,
      audience: this.APP_CLIENT_ID,
      subject: this.SUBJECT,
      expiresIn: payload.exp,
    }
    
    return this.#verifySignature(token, pem, options);
  }

  async authenticateToken(req, res, next) {
    try {
      const {
        headers: {
          authorizationinfo,
        }
      } = req;
      
      const decodedToken = await this.#decodeToken(authorizationinfo);
      
      req.user = decodedToken;
      next();
    } catch (error) {
      const status = error.getStatus?.() || 500;
      const message = error.message || this.ERROR_MESSAGES.GENERAL_ERROR;
      res.status(status).send({ message });
    }
  }
}
