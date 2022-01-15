import nock from "nock";
import { createRequest, createResponse } from "node-mocks-http";
import authorise from "./index";
import TokenGenerator from "./__tests__/TokenGenerator";

const tokenGenerator = new TokenGenerator();
const options = {
  issuer: "http://issuer.com",
  audience: "audience",
  algorithms: "RS256"
};
const currentTime = Math.round(Date.now() / 1000);
const claims = (optionOverides = {}) => ({
  sub: "foo",
  iss: options.issuer,
  aud: options.audience,
  exp: currentTime + 10,
  ...optionOverides,
});

let res;
let next;
let req;

beforeAll(async () => {
  await tokenGenerator.init();

  nock(options.issuer)
    .persist()
    .get("/.well-known/jwks.json")
    .reply(200, { keys: [tokenGenerator.jwk] });
});

describe("A request with a valid access token", () => {
  function setArgs(token) {
    res = createResponse();
    next = jest.fn();
    req = createRequest({
      headers: {
        authorizationinfo: token
      }
    });
  }

  describe('when claims are valid', () => {
    beforeEach(async () => {
      const token = await tokenGenerator.createSignedJWT(claims());
      setArgs(token);
      await authorise(options)(req, res, next);
    });

    test("should add a user object containing the token claims to the request", () => {
      expect(req).toHaveProperty("user", claims());
    });
  
    test("call next()", () => {
      expect(next).toHaveBeenCalled();
    });
  });
  
  [
    {
      description: 'when aud is invalid',
      claims: { aud: 'null' },
    }, {
      description: 'when expiration is invalid',
      claims: { exp: currentTime - 50 },
    }, {
      description: 'when iss is invalid',
      claims: { iss: 'https://test.com' },
  },
].forEach(({
    description,
    claims: claimMock,
  }) => {
    describe(description, () => {
      beforeEach(async () => {
        const token = await tokenGenerator.createSignedJWT(claims(claimMock));
        setArgs(token);
        await authorise(options)(req, res, next);
      });
      
      test("should not call next()", () => {
        expect(next).not.toHaveBeenCalled();
      });
      
      test("should send a 401 response", () => {
        expect(res.statusCode).toEqual(401);
      });
    });
  });
});

describe("A request with an invalid access token", () => {
  beforeEach(async () => {
    res = createResponse();
    next = jest.fn();
    req = createRequest({
      headers: {
        authorizationinfo: null
      }
    });
    await authorise(options)(req, res, next);
  });

  test("should not call next()", () => {
    expect(next).not.toHaveBeenCalled();
  });
  
  test("should send a 401 response", () => {
    expect(res.statusCode).toEqual(401);
  });
});
