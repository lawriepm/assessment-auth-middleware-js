import jwt from "jsonwebtoken";

export default class JwtAuthenticator {
  async #decodeToken(token) {
    if (!token) return false;
    
    return jwt.decode(token);
  }
  
  async authenticateToken(req, res, next) {
    const {
      headers: {
        authorizationinfo,
      }
    } = req;
    const user = await this.#decodeToken(authorizationinfo);
    
    if (!user) {
      res.status(401).send();
      return;
    }

    req.user = user;
    next();
  }
}
