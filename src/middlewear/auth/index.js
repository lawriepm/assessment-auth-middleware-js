import axios from 'axios';
import jwt from "jsonwebtoken";
import jwkToPem from 'jwk-to-pem';


export default class JwtAuthenticator {
  constructor() {
    this.USER_POOL_ID = 'http://issuer.com'; // mock value for verifying claims
    this.CLIENT_ID = 'audience'; // mock value for verifying claims
  }

  async #fetchKeys() {
    const { data: { keys } } = await axios.get(`${this.USER_POOL_ID}/.well-known/jwks.json`);
    return keys;
  }

  #validateClaims(decodedToken) {
    const settings = [{
      key: 'exp',
      isValid: (arg) => Math.round(Date.now() / 1000) < arg
    }, {
      key: 'iss',
      isValid: (arg) => arg.endsWith(this.USER_POOL_ID)
    }, {
      key: 'aud',
      isValid: (arg) => arg === this.CLIENT_ID,
    }];

    return settings.every((setting) => setting.isValid(decodedToken[setting.key]));
  }

  #decodeTokenHeader(token) {
    const [headerEncoded] = token.split('.');
    const buff = new Buffer(headerEncoded, 'base64');
    const text = buff.toString('ascii');
    return JSON.parse(text);
  }

  #verifySignatureAndClaims(err, decodedToken) {
    if (err) {
      return [false];
    };

    const hasValidClaims = this.#validateClaims(decodedToken);
    if (!hasValidClaims) {
      return [false];
    }

    return [true, decodedToken];
  }

  async #decodeToken(token) {
    if (!token) return [false];
    const keys = await this.#fetchKeys();
    const { kid, alg } = this.#decodeTokenHeader(token);
    const key = keys.find(({ kid: keyId }) => kid === keyId);
    const pem = jwkToPem(key);
    return jwt.verify(token, pem, { algorithms: [alg] }, this.#verifySignatureAndClaims.bind(this));
  }

  async authenticateToken(req, res, next) {
    try {
      const {
        headers: {
          authorizationinfo,
        }
      } = req;
      
      const [isValid, decodedToken] = await this.#decodeToken(authorizationinfo);
      
      if (!isValid) {
        res.status(401).send();
        return;
      }
      
      req.user = decodedToken;
      next();
    } catch (error) {
      res.status(500).send();
    }
  }
}
