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
const claims = (claimsOveride = {}) => ({
  sub: "foo",
  iss: options.issuer,
  aud: options.audience,
  exp: currentTime + 10,
  token_use: "access",
  ...claimsOveride,
});

let res;
let next;
let req;

function setArgs(token) {
  res = createResponse();
  next = jest.fn();
  req = createRequest({
    headers: {
      authorizationinfo: token
    }
  });
}

function runInvalidTokenTests(messageAssertion) {
  test("should not call next()", () => {
    expect(next).not.toHaveBeenCalled();
  });
  
  test("should send a 401 response", () => {
    expect(res.statusCode).toEqual(401);
  });

  test(`should send message ${messageAssertion}`, () => {
    const { message } = res._getData();
    expect(message).toEqual(messageAssertion);
  }); 
}

beforeAll(async () => {
  await tokenGenerator.init();

  nock(options.issuer)
    .persist()
    .get("/.well-known/jwks.json")
    .reply(200, { keys: [tokenGenerator.jwk] });
});

describe("A request with a valid access token", () => {
  describe("with valid claims", () => {
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
      key: "iss",
      value: "https:/test.com",
      error: "jwt issuer invalid.",
    },
    {
      key: "exp",
      value: currentTime - 200,
      error: "jwt expired",
    },
    {
      key: "aud",
      value: "testaudience",
      error: "jwt audience invalid.",
    },
    {
      key: "sub",
      value: "bar",
      error: "jwt subject invalid.",
    },
    {
      key: "token_use",
      value: "id",
      error: "jwt token_use invalid.",
    },
  ].forEach(({ key, value, error }) => {
    describe(`and an invalid ${key} claim`, () => {
      beforeEach(async () => {
        const token = await tokenGenerator.createSignedJWT(claims({ [key]: value }));
        setArgs(token);
        await authorise(options)(req, res, next);
      });

      runInvalidTokenTests(error);
    });
  });
});

describe("A request with a null token", () => {
  beforeEach(async () => {
    setArgs(null);
    await authorise(options)(req, res, next);
  });
  
  runInvalidTokenTests("no jwt provided.");
});

describe("A request with an invalid access token", () => {
  beforeEach(async () => {
    setArgs("this.is.an.invalid.token");
    await authorise(options)(req, res, next);
  });

  runInvalidTokenTests("jwt payload or header invalid.");
});
