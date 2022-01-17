import axios from "axios";
import jwt from "jsonwebtoken";
import jwkToPem from "jwk-to-pem";
import { AuthenticationError } from "./error";

export default class JwtAuthenticator {
  constructor() {
    this.USER_POOL = "http://issuer.com"; // mock value for verifying claims real value may look like https://cognito-idp.us-east-1.amazonaws.com/<userpoolID>
  }

  async #fetchKeys() {
    const { data: { keys } } = await axios.get(`${this.USER_POOL}/.well-known/jwks.json`);
    return keys;
  }

  #verifySignature(token, pem, options) {
    return new Promise((resolve, reject) => {
      jwt.verify(token, pem, options, (err, decodedToken) => {
        if (err) {
          return reject(new AuthenticationError());
        };

        resolve(decodedToken);
      })
    })
  }

  async #decodeToken(token) {
    if (!token) throw new AuthenticationError();
    
    const decodedToken = jwt.decode(token, { complete: true });
    if (!decodedToken) throw new AuthenticationError();
    
    const { header: { kid, alg }, payload } = decodedToken;
    
    const keys = await this.#fetchKeys();
    const key = keys.find(({ kid: keyId }) => kid === keyId);
    const pem = jwkToPem(key);

    const options = {
      algorithms: [alg],
      issuer: payload.iss,
      audience: payload.aud,
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
      res.status(status).send();
    }
  }
}
