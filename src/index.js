import JwtAuthenticator from './middlewear/auth';
const authenticator = new JwtAuthenticator()

const authorize =
  (options) =>
    async (
      req,
      res,
      next
    ) => authenticator.authenticateToken(req, res, next);

export default authorize;
