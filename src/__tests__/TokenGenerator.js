import { JWK, JWS } from "node-jose";

class TokenGenerator {
  #key;

  async init () {
    const keystore = JWK.createKeyStore();
    this.#key = await keystore.generate("RSA", 2048, {
      alg: "RS256",
      use: "sig"
    });
  }

  get jwk () {
    return this.#key.toJSON();
  }

  async createSignedJWT (payload) {
    const payloadJson = JSON.stringify(payload);
    return await JWS.createSign(
      { compact: true, fields: { typ: "jwt" } },
      this.#key
    )
      .update(payloadJson)
      .final();
  }
}

export default TokenGenerator;
