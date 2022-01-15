import axios from 'axios';
import jwt from "jsonwebtoken";
import jwkToPem from 'jwk-to-pem';


export default class JwtAuthenticator {
  async #getKeys() {
    const { data: { keys } } = await axios.get('http://issuer.com/.well-known/jwks.json');
    return keys;
  }

  async #decodeToken(token) {
    if (!token) return [false];

    const keys = await this.#getKeys();
    const pem = jwkToPem(keys[0]);

    return jwt.verify(token, pem, { algorithms: ['RS256'] }, function(err, decodedToken) {
      if (err) {
        return [false];
      };

      return [true, decodedToken];
    });
  }
  
  async authenticateToken(req, res, next) {
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
  }
}
