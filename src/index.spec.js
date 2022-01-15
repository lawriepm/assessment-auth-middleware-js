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
const claims = {
  sub: "foo",
  iss: options.issuer,
  aud: options.audience,
  exp: currentTime + 10
};

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
  beforeEach(async () => {
    const token = await tokenGenerator.createSignedJWT(claims);
    res = createResponse();
    next = jest.fn();
    req = createRequest({
      headers: {
        authorizationinfo: token
      }
    });

    await authorise(options)(req, res, next);
  });

  test("should add a user object containing the token claims to the request", () => {
    expect(req).toHaveProperty("user", claims);
  });

  test("call next()", () => {
    expect(next).toHaveBeenCalled();
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
