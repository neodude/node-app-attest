import cbor from "cbor";

import { parseAppleAppAttestAuthenticatorData } from "../src/authenticatorData.js";
import * as appAttest from "../src/index.js";
import iOS27AuthenticatorData from "./fixtures/authenticator-data-ios27.json";

const OFFICIAL_IOS_27_AUTHENTICATOR_DATA = Buffer.from(
  iOS27AuthenticatorData.authenticatorData,
  "base64",
);

function withExtensions(extensions) {
  const authenticatorData = Buffer.from(OFFICIAL_IOS_27_AUTHENTICATOR_DATA);
  const credentialIdLength = authenticatorData.readUInt16BE(53);
  const credentialDataEnd = 55 + credentialIdLength;
  const cosePublicKey = cbor.decodeAllSync(
    authenticatorData.subarray(credentialDataEnd),
  )[0];

  authenticatorData[32] |= 0x80;
  return Buffer.concat([
    authenticatorData.subarray(0, credentialDataEnd),
    cbor.encode(cosePublicKey),
    cbor.encode(extensions),
  ]);
}

describe("parseAppleAppAttestAuthenticatorData", () => {
  it("parses Apple’s iOS 27 attestation authenticator-data fixture", () => {
    expect(
      parseAppleAppAttestAuthenticatorData(OFFICIAL_IOS_27_AUTHENTICATOR_DATA),
    ).toEqual({ validationCategory: 1, bundleVersion: "1" });
  });

  it("exports both public verifiers", () => {
    expect(appAttest).toEqual(
      expect.objectContaining({
        verifyAssertion: expect.any(Function),
        verifyAttestation: expect.any(Function),
      }),
    );
  });

  it("permits pre-iOS 27 authenticator data without extensions", () => {
    const authenticatorData = Buffer.alloc(37);

    expect(
      parseAppleAppAttestAuthenticatorData(authenticatorData, {
        hasAttestedCredentialData: false,
      }),
    ).toEqual({});
  });

  it("rejects a partial iOS 27 extension map", () => {
    expect(() =>
      parseAppleAppAttestAuthenticatorData(
        withExtensions({ apple_bundle_version_01: "1" }),
        { hasAttestedCredentialData: true },
      ),
    ).toThrow("invalid authenticator data extensions");
  });

  it("rejects a malformed iOS 27 validation category", () => {
    expect(() =>
      parseAppleAppAttestAuthenticatorData(
        withExtensions({
          apple_bundle_version_01: "1",
          apple_validation_category_01: 1,
        }),
        { hasAttestedCredentialData: true },
      ),
    ).toThrow("invalid authenticator data extensions");
  });

  it.each([
    [Buffer.alloc(36), undefined],
    [Buffer.alloc(37), { hasAttestedCredentialData: true }],
    [Buffer.alloc(54), { hasAttestedCredentialData: true }],
  ])("rejects malformed authenticator data", (authenticatorData, options) => {
    expect(() =>
      parseAppleAppAttestAuthenticatorData(authenticatorData, options),
    ).toThrow("invalid authenticator data");
  });

  it("rejects unauthenticated trailing data", () => {
    expect(() =>
      parseAppleAppAttestAuthenticatorData(Buffer.alloc(38), {
        hasAttestedCredentialData: false,
      }),
    ).toThrow("invalid authenticator data extensions");
  });

  it("rejects extension data that is missing or contains extra CBOR items", () => {
    const missingExtensionData = Buffer.alloc(37);
    missingExtensionData[32] = 0x80;
    const extraExtensionData = Buffer.concat([
      Buffer.from([
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0x80, 0, 0, 0, 0,
      ]),
      cbor.encode({}, {}),
    ]);

    for (const authenticatorData of [
      missingExtensionData,
      extraExtensionData,
    ]) {
      expect(() =>
        parseAppleAppAttestAuthenticatorData(authenticatorData, {
          hasAttestedCredentialData: false,
        }),
      ).toThrow("invalid authenticator data extensions");
    }
  });

  it("rejects a malformed credential public key", () => {
    const authenticatorData = Buffer.concat([
      Buffer.alloc(55),
      cbor.encode({}),
    ]);
    authenticatorData[32] = 0x40;

    expect(() =>
      parseAppleAppAttestAuthenticatorData(authenticatorData),
    ).toThrow("invalid authenticator data");
  });

  it.each([
    {
      apple_bundle_version_01: "1",
      apple_validation_category_01: Buffer.alloc(2),
    },
    {
      apple_bundle_version_01: 1,
      apple_validation_category_01: Buffer.alloc(4),
    },
    {
      apple_bundle_version_01: "",
      apple_validation_category_01: Buffer.alloc(4),
    },
  ])("rejects malformed extension values", (extensions) => {
    expect(() =>
      parseAppleAppAttestAuthenticatorData(withExtensions(extensions)),
    ).toThrow("invalid authenticator data extensions");
  });

  it("rejects an extension map without Apple’s required fields", () => {
    expect(() =>
      parseAppleAppAttestAuthenticatorData(
        withExtensions({ unrelated_extension: true }),
      ),
    ).toThrow("invalid authenticator data extensions");
  });

  it("permits unrelated extension identifiers alongside Apple’s required fields", () => {
    expect(
      parseAppleAppAttestAuthenticatorData(
        withExtensions({
          apple_bundle_version_01: "1",
          apple_validation_category_01: Buffer.from([5, 0, 0, 0]),
          unrelated_extension: true,
        }),
      ),
    ).toEqual({ validationCategory: 5, bundleVersion: "1" });
  });

  it("rejects invalid CBOR and malformed credential lengths", () => {
    const invalidCbor = Buffer.alloc(38);
    invalidCbor[37] = 0xff;
    const truncatedCredential = Buffer.alloc(55);
    truncatedCredential[32] = 0x40;
    truncatedCredential.writeUInt16BE(1, 53);
    const incompleteCredentialLength = Buffer.alloc(54);
    incompleteCredentialLength[32] = 0x40;
    const missingCredentialPublicKey = Buffer.alloc(55);
    missingCredentialPublicKey[32] = 0x40;

    for (const authenticatorData of [
      invalidCbor,
      truncatedCredential,
      incompleteCredentialLength,
      missingCredentialPublicKey,
    ]) {
      expect(() =>
        parseAppleAppAttestAuthenticatorData(authenticatorData),
      ).toThrow();
    }
  });

  it("rejects non-object extension maps", () => {
    const authenticatorData = Buffer.concat([
      Buffer.from([
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0x80, 0, 0, 0, 0,
      ]),
      cbor.encode([]),
    ]);

    expect(() =>
      parseAppleAppAttestAuthenticatorData(authenticatorData, {
        hasAttestedCredentialData: false,
      }),
    ).toThrow("invalid authenticator data extensions");
  });
});
