import { JwtAuthenticator } from "./middlewear";
const authenticator = new JwtAuthenticator()

const authorize =
  () =>
    async (
      req,
      res,
      next
    ) => authenticator.authenticateToken(req, res, next);

export default authorize;
