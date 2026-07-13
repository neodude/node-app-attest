/**
 * Parse the optional WebAuthn extension map from App Attest authenticator data.
 *
 * Authenticator data emitted before iOS 27 has no extension data. When an
 * extension map is appended (including Apple’s current guide sample), it is
 * authenticated by the attestation nonce or assertion signature before this
 * parser is called by the public verifiers.
 *
 * @returns {{ validationCategory?: number, bundleVersion?: string }}
 */
export function parseAppleAppAttestAuthenticatorData(
  authenticatorData: any,
  options?: {},
): {
  validationCategory?: number;
  bundleVersion?: string;
};
//# sourceMappingURL=authenticatorData.d.ts.map
