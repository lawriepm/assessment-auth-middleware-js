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

function runInvalidTokenTests(
  messageAssertion,
  statusAssertion = 401,
) {
  test("should not call next()", () => {
    expect(next).not.toHaveBeenCalled();
  });
  
  test(`should send a ${statusAssertion} response`, () => {
    expect(res.statusCode).toEqual(statusAssertion);
  });

  test(`should send message ${messageAssertion}`, () => {
    const { message } = res._getData();
    expect(message).toEqual(messageAssertion);
  }); 
}

beforeAll(async () => {
  await tokenGenerator.init();
});

afterEach(() => {
  nock.cleanAll();
});

function mockJwk(
  responseBody = { keys: [tokenGenerator.jwk] },
  responseStatus = 200,
) {
  nock(options.issuer)
    .persist()
    .get("/.well-known/jwks.json")
    .reply(responseStatus, responseBody);
}

describe("A request with a valid access token", () => {
  describe("with valid claims", () => {
    beforeEach(async () => {
      mockJwk();
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
        mockJwk();
        const token = await tokenGenerator.createSignedJWT(claims({ [key]: value }));
        setArgs(token);
        await authorise(options)(req, res, next);
      });

      runInvalidTokenTests(error);
    });
  });

  describe("and an undefined jwk", () => {
    beforeEach(async () => {
      
      const invalidJwk = {};
      const token = await tokenGenerator.createSignedJWT(claims());
      mockJwk({ keys: [invalidJwk] });
      setArgs(token);
      await authorise(options)(req, res, next);
    });
  
    runInvalidTokenTests("no jwk found.");
  });

  describe("and an invalid signature", () => {
    beforeEach(async () => {
      
      const token = await tokenGenerator.createSignedJWT(claims());
      const invalidJwk = {
        ...tokenGenerator.jwk,
        n: `${tokenGenerator.jwk.n}12345`,
      };
      mockJwk({ keys: [invalidJwk] });
      setArgs(token);
      await authorise(options)(req, res, next);
    });
  
    runInvalidTokenTests("invalid signature");
  });

  describe("and a failed request to fetch keys", () => {
    beforeEach(async () => {
      
      const token = await tokenGenerator.createSignedJWT(claims());
      mockJwk(undefined, 500);
      setArgs(token);
      await authorise(options)(req, res, next);
    });
  
    runInvalidTokenTests("Request failed with status code 500", 500);
  });
});

describe("A request with a null token", () => {
  beforeEach(async () => {
    mockJwk();
    setArgs(null);
    await authorise(options)(req, res, next);
  });
  
  runInvalidTokenTests("no jwt provided.");
});

describe("A request with an invalid access token", () => {
  beforeEach(async () => {
    mockJwk();
    setArgs("this.is.an.invalid.token");
    await authorise(options)(req, res, next);
  });

  runInvalidTokenTests("jwt payload or header invalid.");
});
