import cbor from "cbor";

const AUTHENTICATOR_DATA_HEADER_LENGTH = 37;
const ATTESTED_CREDENTIAL_DATA_FLAG = 0x40;
const EXTENSION_DATA_FLAG = 0x80;
const AAGUID_LENGTH = 16;
const CREDENTIAL_ID_LENGTH_FIELD_LENGTH = 2;
const APPLE_VALIDATION_CATEGORY_KEY = "apple_validation_category_01";
const APPLE_BUNDLE_VERSION_KEY = "apple_bundle_version_01";

function isObject(value) {
  return (
    typeof value === "object" &&
    value !== null &&
    !Array.isArray(value) &&
    !Buffer.isBuffer(value) &&
    !(value instanceof Map)
  );
}

function parseAppleAppAttestExtensions(value) {
  if (!isObject(value)) {
    throw new Error("invalid authenticator data extensions");
  }

  const hasValidationCategory = Object.hasOwn(
    value,
    APPLE_VALIDATION_CATEGORY_KEY,
  );
  const hasBundleVersion = Object.hasOwn(value, APPLE_BUNDLE_VERSION_KEY);

  if (hasValidationCategory !== hasBundleVersion) {
    throw new Error("invalid authenticator data extensions");
  }

  if (!hasValidationCategory) {
    return {};
  }

  const validationCategory = value[APPLE_VALIDATION_CATEGORY_KEY];
  const bundleVersion = value[APPLE_BUNDLE_VERSION_KEY];

  // Apple encodes its UInt32 extension value as four little-endian bytes.
  if (
    !Buffer.isBuffer(validationCategory) ||
    validationCategory.byteLength !== 4 ||
    typeof bundleVersion !== "string" ||
    bundleVersion.length === 0
  ) {
    throw new Error("invalid authenticator data extensions");
  }

  return {
    validationCategory: validationCategory.readUInt32LE(),
    bundleVersion,
  };
}

/**
 * Parse the optional WebAuthn extension map from App Attest authenticator data.
 *
 * Authenticator data emitted before iOS 27 has no extension data. When an
 * extension map is appended (including Apple’s current guide sample), it is
 * authenticated by the attestation nonce or assertion signature before this
 * parser is called by the public verifiers.
 */
export function parseAppleAppAttestAuthenticatorData(
  authenticatorData,
  options = {},
) {
  if (
    !Buffer.isBuffer(authenticatorData) ||
    authenticatorData.byteLength < AUTHENTICATOR_DATA_HEADER_LENGTH
  ) {
    throw new Error("invalid authenticator data");
  }

  const flags = authenticatorData[32];
  const hasAttestedCredentialData =
    options.hasAttestedCredentialData ??
    (flags & ATTESTED_CREDENTIAL_DATA_FLAG) !== 0;
  const hasExtensionData = (flags & EXTENSION_DATA_FLAG) !== 0;
  let offset = AUTHENTICATOR_DATA_HEADER_LENGTH;

  if (hasAttestedCredentialData) {
    if ((flags & ATTESTED_CREDENTIAL_DATA_FLAG) === 0) {
      throw new Error("invalid authenticator data");
    }

    const credentialIdLengthOffset = offset + AAGUID_LENGTH;
    const credentialIdOffset =
      credentialIdLengthOffset + CREDENTIAL_ID_LENGTH_FIELD_LENGTH;

    if (authenticatorData.byteLength < credentialIdOffset) {
      throw new Error("invalid authenticator data");
    }

    const credentialIdLength = authenticatorData.readUInt16BE(
      credentialIdLengthOffset,
    );
    offset = credentialIdOffset + credentialIdLength;

    if (authenticatorData.byteLength < offset) {
      throw new Error("invalid authenticator data");
    }

    if (authenticatorData.byteLength === offset) {
      throw new Error("invalid authenticator data");
    }
  }

  if (
    !hasAttestedCredentialData &&
    !hasExtensionData &&
    offset === authenticatorData.byteLength
  ) {
    return {};
  }

  let decoded;
  try {
    decoded = cbor.decodeAllSync(authenticatorData.subarray(offset));
  } catch {
    throw new Error("invalid authenticator data extensions");
  }

  const hasParsedExtensionData =
    hasAttestedCredentialData && decoded.length === 2;
  const expectedItemCount = hasAttestedCredentialData
    ? hasParsedExtensionData
      ? 2
      : 1
    : hasExtensionData
      ? 1
      : 0;
  if (
    decoded.length !== expectedItemCount ||
    (hasExtensionData && !hasParsedExtensionData && hasAttestedCredentialData)
  ) {
    throw new Error("invalid authenticator data extensions");
  }

  if (hasAttestedCredentialData && !(decoded[0] instanceof Map)) {
    throw new Error("invalid authenticator data");
  }

  if (!hasExtensionData && !hasParsedExtensionData) {
    return {};
  }

  return parseAppleAppAttestExtensions(decoded.at(-1));
}
