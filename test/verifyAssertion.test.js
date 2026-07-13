import verifyAssertion from "../src/verifyAssertion.js";
import cbor from "cbor";
import { createHash, generateKeyPairSync, sign } from "crypto";

const ASSERTION = Buffer.from(
  "omlzaWduYXR1cmVYRzBFAiBB8BGAwkmFCg1M5J0mOYEun0SUN1/lse79/7ypG9WiMQIhAIHvqj7eg59B1PMFX1CN4GMGlsgfFtdL30pHCf7G/dNRcWF1dGhlbnRpY2F0b3JEYXRhWCXKPdw7T3iujcFZbHVrHX0mDSMrNms5PzEbrFbQPRA6rEAAAAAB",
  "base64",
);
const PUBLIC_KEY =
  "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEg69t2YzgcPTLUx8Zgu+rbcikeaEL\n8Ppb+HG0QTIulz8YUB9tgv1pDRruWk87nZC3our56pzIWaqXEbaWyamdzA==\n-----END PUBLIC KEY-----\n";
const BUNDLE_IDENTIFIER = "io.uebelacker.AppAttestExample";
const TEAM_IDENTIFIER = "V8H6LQ9448";

describe("verifyAssertion", () => {
  it("should verify assertion successfully", async () => {
    verifyAssertion({
      assertion: ASSERTION,
      payload:
        '{"subject":"Lorem ipsum","message":"Lorem ipsum dolor sit amet, consectetur adipiscing elit."}',
      publicKey: PUBLIC_KEY,
      bundleIdentifier: BUNDLE_IDENTIFIER,
      teamIdentifier: TEAM_IDENTIFIER,
    });
  });

  it("should verify bundleIdentifier", () => {
    expect(() => {
      verifyAssertion({ teamIdentifier: TEAM_IDENTIFIER });
    }).toThrow("bundleIdentifier is required");
  });

  it("should verify teamIdentifier", () => {
    expect(() => {
      verifyAssertion({ bundleIdentifier: BUNDLE_IDENTIFIER });
    }).toThrow("teamIdentifier is required");
  });

  it("should verify assertion", () => {
    expect(() => {
      verifyAssertion({
        bundleIdentifier: BUNDLE_IDENTIFIER,
        teamIdentifier: TEAM_IDENTIFIER,
      });
    }).toThrow("assertion is required");
  });

  it("should verify payload", () => {
    expect(() => {
      verifyAssertion({
        assertion: ASSERTION,
        bundleIdentifier: BUNDLE_IDENTIFIER,
        teamIdentifier: TEAM_IDENTIFIER,
      });
    }).toThrow("payload is required");
  });

  it("should verify publicKey", () => {
    expect(() => {
      verifyAssertion({
        assertion: ASSERTION,
        payload:
          '{"subject":"Lorem ipsum","message":"Lorem ipsum dolor sit amet, consectetur adipiscing elit."}',
        bundleIdentifier: BUNDLE_IDENTIFIER,
        teamIdentifier: TEAM_IDENTIFIER,
      });
    }).toThrow("publicKey is required");
  });

  it("should throw invalid assertion", () => {
    expect(() => {
      verifyAssertion({
        assertion: Buffer.from("invalid-assertion"),
        payload:
          '{"subject":"Lorem ipsum","message":"Lorem ipsum dolor sit amet, consectetur adipiscing elit."}',

        publicKey: PUBLIC_KEY,
        bundleIdentifier: BUNDLE_IDENTIFIER,
        teamIdentifier: TEAM_IDENTIFIER,
      });
    }).toThrow("invalid assertion");
  });

  it("should throw invalid signature", () => {
    expect(() => {
      verifyAssertion({
        assertion: ASSERTION,
        payload: "{}",
        publicKey: PUBLIC_KEY,
        bundleIdentifier: BUNDLE_IDENTIFIER,
        teamIdentifier: TEAM_IDENTIFIER,
      });
    }).toThrow("invalid signature");
  });

  it("should throw invalid appId", () => {
    expect(() => {
      verifyAssertion({
        assertion: ASSERTION,
        payload:
          '{"subject":"Lorem ipsum","message":"Lorem ipsum dolor sit amet, consectetur adipiscing elit."}',
        publicKey: PUBLIC_KEY,
        teamIdentifier: TEAM_IDENTIFIER,
        bundleIdentifier: "INVALID",
      });
    }).toThrow("appId does not match");
  });

  it("should throw invalid signCount", () => {
    expect(() => {
      verifyAssertion({
        assertion: ASSERTION,
        payload:
          '{"subject":"Lorem ipsum","message":"Lorem ipsum dolor sit amet, consectetur adipiscing elit."}',
        publicKey: PUBLIC_KEY,
        bundleIdentifier: BUNDLE_IDENTIFIER,
        teamIdentifier: TEAM_IDENTIFIER,
        signCount: 10,
      });
    }).toThrow("invalid signCount");
  });

  it("returns iOS 27 extensions authenticated by the assertion signature", () => {
    const { privateKey, publicKey } = generateKeyPairSync("ec", {
      namedCurve: "prime256v1",
    });
    const payload = "signed iOS 27 assertion";
    const authenticatorData = Buffer.concat([
      createHash("sha256")
        .update(`${TEAM_IDENTIFIER}.${BUNDLE_IDENTIFIER}`)
        .digest(),
      Buffer.from([0x80]),
      Buffer.from([0, 0, 0, 1]),
      cbor.encode({
        apple_bundle_version_01: "42",
        apple_validation_category_01: Buffer.from([5, 0, 0, 0]),
      }),
    ]);
    const nonce = createHash("sha256")
      .update(
        Buffer.concat([
          authenticatorData,
          createHash("sha256").update(payload).digest(),
        ]),
      )
      .digest();
    const assertion = cbor.encode({
      authenticatorData,
      signature: sign("sha256", nonce, privateKey),
    });

    expect(
      verifyAssertion({
        assertion,
        payload,
        publicKey: publicKey.export({ type: "spki", format: "pem" }),
        bundleIdentifier: BUNDLE_IDENTIFIER,
        teamIdentifier: TEAM_IDENTIFIER,
        signCount: 0,
      }),
    ).toEqual({
      signCount: 1,
      validationCategory: 5,
      bundleVersion: "42",
    });
  });
});
