import axios from "axios";
import jwt from "jsonwebtoken";
import jwkToPem from "jwk-to-pem";

export default class JwtAuthenticator {
  constructor() {
    this.USER_POOL = "http://issuer.com"; // mock value for verifying claims real value may look like https://cognito-idp.us-east-1.amazonaws.com/<userpoolID>
  }

  async #fetchKeys() {
    const { data: { keys } } = await axios.get(`${this.USER_POOL}/.well-known/jwks.json`);
    return keys;
  }

  #verifySignature(err, decodedToken) {
    if (err) {
      return [false];
    };

    return [true, decodedToken];
  }

  async #decodeToken(token) {
    if (!token) return [false];
    
    const decodedToken = jwt.decode(token, { complete: true });
    if (!decodedToken) return [false];
    
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
    
    return jwt.verify(token, pem, options, this.#verifySignature.bind(this));
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
