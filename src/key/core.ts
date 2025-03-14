import {
  type Flag,
  format,
  ImplementationError,
  ImplementationErrorCode,
  type JWK,
  type JWKEC,
  multi,
  type VerificationMethodJwk,
  type VerificationMethodMultibase,
} from "@herculas/vc-data-integrity"
import { key } from "@herculas/bbs-signature"

import { BbsKeypair } from "./keypair.ts"

import * as PREFIX_CONSTANT from "../constant/prefix.ts"
import * as SUITE_CONSTANT from "../constant/suite.ts"

/**
 * Generate a BLS12-381 keypair for BBS signatures.
 *
 * @param {Uint8Array} [seed] The seed to use for keypair generation.
 *
 * @returns {object} The BLS12-381 keypair, containing a secret key and a public key in Uint8Array format.
 */
export function generateKeypair(seed?: Uint8Array): {
  secretKey: Uint8Array
  publicKey: Uint8Array
} {
  if (!seed) {
    seed = new Uint8Array(SUITE_CONSTANT.DEFAULT_KEY_MATERIAL_LENGTH)
    crypto.getRandomValues(seed)
  }
  const material = format.bytesToHex(seed)
  const { secretKey, publicKey } = key.createPair(material)
  return {
    secretKey: format.hexToBytes(secretKey),
    publicKey: format.hexToBytes(publicKey),
  }
}

/**
 * Encode a key material into a multibase-encoded string.
 *
 * @param {Uint8Array} material The key material in Uint8Array format.
 * @param {Flag} flag The flag to determine if the key is private or public.
 *
 * @returns {string} The multibase-encoded key string.
 */
export function materialToMultibase(material: Uint8Array, flag: Flag): string {
  const multiPrefix = flag === "private" ? PREFIX_CONSTANT.PRIVATE_KEY_MULTIBASE : PREFIX_CONSTANT.PUBLIC_KEY_MULTIBASE
  const expectedLength = flag === "private" ? SUITE_CONSTANT.PRIVATE_KEY_LENGTH : SUITE_CONSTANT.PUBLIC_KEY_LENGTH

  if (material.length !== expectedLength) {
    throw new ImplementationError(
      ImplementationErrorCode.INVALID_KEYPAIR_LENGTH,
      "keypair/core#materialToMultibase",
      `The ${flag} key material should be a ${expectedLength}-octet array!`,
    )
  }

  const multibase = format.concatenate(multiPrefix, material)
  return multi.base58btc.encode(multibase)
}

/**
 * Decode a multibase encoded private or public key into a Uint8Array key material, and check the key material against
 * the prefix from the specification.
 *
 * @param {string} multibase A multibase-encoded private or public key string.
 * @param {Flag} flag The flag to determine if the key is private or public.
 *
 * @returns {Uint8Array} The decoded key material in Uint8Array format.
 */
export function multibaseToMaterial(multibase: string, flag: Flag): Uint8Array {
  const key = multi.base58btc.decode(multibase)
  const expectedPrefix = flag === "private"
    ? PREFIX_CONSTANT.PRIVATE_KEY_MULTIBASE
    : PREFIX_CONSTANT.PUBLIC_KEY_MULTIBASE

  if (!expectedPrefix.every((value, index) => key[index] === value)) {
    throw new ImplementationError(
      ImplementationErrorCode.DECODING_ERROR,
      "keypair/core#multibaseToMaterial",
      "The provided multibase string does not match the specified prefix!",
    )
  }

  return key.slice(expectedPrefix.length)
}

/**
 * Calculate the thumbprint of a JWK instance using SHA-256 hashing algorithm.
 *
 * @param {JWK} jwk The JWK instance to calculate the thumbprint.
 *
 * @returns {Promise<string>} Resolve to the thumbprint of the JWK instance.
 */
async function getJwkThumbprint(jwk: JWK): Promise<string> {
  const data = new TextEncoder().encode(JSON.stringify(jwk))
  const hash = await crypto.subtle.digest("SHA-256", data)
  return multi.base64url.encode(new Uint8Array(hash))
}

/**
 * Convert a key material into a `JWKEC` object. The flag determines if the key is private or public. When the key is
 * private, the `d` field is included in the resulted object.
 *
 * @param {Uint8Array} material A BBS private key or public key material.
 * @param {Flag} flag The flag to determine if the key is private or public.
 *
 * @returns {JWKEC} An object representing a JSON Web Key.
 */
export function keyToJwk(material: Uint8Array, flag: Flag): JWKEC {
  const expectedLength = flag === "private" ? SUITE_CONSTANT.PRIVATE_KEY_LENGTH : SUITE_CONSTANT.PUBLIC_KEY_LENGTH
  const usage = flag === "private" ? ["sign"] : ["verify"]

  if (material.length !== expectedLength) {
    throw new ImplementationError(
      ImplementationErrorCode.INVALID_KEYPAIR_LENGTH,
      "keypair/core#keyToJwk",
      `The ${flag} key material should be a ${expectedLength}-octet array!`,
    )
  }

  const serialized = multi.base64url.encode(material)

  const jwk: JWKEC = {
    kty: SUITE_CONSTANT.JWK_TYPE,
    use: SUITE_CONSTANT.JWK_USE,
    key_ops: usage,
    alg: SUITE_CONSTANT.ALGORITHM,
    ext: true,
    crv: SUITE_CONSTANT.ALGORITHM,
    x: flag === "public" ? serialized : "",
    y: "",
    d: flag === "public" ? undefined : serialized,
  }

  return jwk
}

/**
 * Convert a `JWKEC` key object into a key material. The flag determines if the key is private or public. When the key
 * is private, the `d` field MUST be provided in the `jwk` input.
 *
 * @param {JWKEC} jwk An object representing a JSON Web Key.
 * @param {Flag} flag The flag to determine if the key is private or public.
 *
 * @returns {Uint8Array} The key material in Uint8Array format.
 */
export function jwkToKey(jwk: JWKEC, flag: Flag): Uint8Array {
  if ((flag === "private" && !jwk.d) || (flag === "public" && jwk.x === "")) {
    throw new ImplementationError(
      ImplementationErrorCode.INVALID_KEYPAIR_CONTENT,
      "keypair/core#jwkToKey",
      `The provided ${flag} key object does not contain the required field!`,
    )
  }

  const serialized = flag === "public" ? jwk.x : jwk.d!
  return multi.base64url.decode(serialized)
}

/**
 * Export a BBS keypair instance into a verification method containing a keypair in JWK format.
 *
 * @param {BbsKeypair} keypair A BBS keypair instance.
 * @param {Flag} flag The flag to determine if the key is private or public.
 *
 * @returns {Promise<VerificationMethodJwk>} A verification method containing a keypair in JWK format.
 */
export async function keypairToJwk(keypair: BbsKeypair, flag: Flag): Promise<VerificationMethodJwk> {
  // check the controller and identifier
  if (!keypair.controller || !keypair.id) {
    throw new ImplementationError(
      ImplementationErrorCode.INVALID_KEYPAIR_CONTENT,
      "keypair/core#keypairToJwk",
      "The keypair should have a controller and an identifier!",
    )
  }

  // prepare the document for export
  const document: VerificationMethodJwk = {
    id: keypair.id!,
    type: SUITE_CONSTANT.KEYPAIR_DOCUMENT_TYPE_JWK,
    controller: keypair.controller!,
    expires: keypair.revoked ? format.toW3CTimestamp(keypair.revoked) : undefined,
    revoked: keypair.revoked ? format.toW3CTimestamp(keypair.revoked) : undefined,
  }

  // consider the following 5 cases:
  //
  // 1. The `flag` is `private`, but the private key is missing. Throw an error.
  // 2. The `flag` is `private`, and the public key is missing. Export the private key only.
  // 3. The `flag` is `private`, and the public key is presented. Export the public key and set the `id` accordingly.
  // 4. The `flag` is `public`, but the public key is missing. Throw an error.
  // 5. The `flag` is `public`, and the public key is presented. Export the public key, and set the `id` accordingly.

  if (flag === "private") {
    if (!keypair.privateKey) {
      throw new ImplementationError(
        ImplementationErrorCode.INVALID_KEYPAIR_CONTENT,
        "keypair/core#keypairToJwk",
        "The private key is missing from the keypair!",
      )
    } else {
      document.secretKeyJwk = keyToJwk(keypair.privateKey, "private")
    }
  }

  if (keypair.publicKey) {
    document.publicKeyJwk = keyToJwk(keypair.publicKey, "public")
    document.id = `${keypair.controller}#${await getJwkThumbprint(document.publicKeyJwk)}`
  } else if (flag === "public") {
    throw new ImplementationError(
      ImplementationErrorCode.INVALID_KEYPAIR_CONTENT,
      "keypair/core#keypairToJwk",
      "The public key is missing from the keypair!",
    )
  }

  return document
}

/**
 * Import a keypair from a serialized verification method containing a keypair in JWK format.
 *
 * @param {VerificationMethodJwk} verificationMethod A verification method fetched from an external source.
 * @param {Date} [expires] The expiration date of the keypair.
 * @param {Date} [revoked] The revoked date of the keypair.
 *
 * @returns {Promise<BbsKeypair>} Resolve to a BBS keypair instance.
 */
export function jwkToKeypair(verificationMethod: VerificationMethodJwk, expires?: Date, revoked?: Date): BbsKeypair {
  const keypair = new BbsKeypair(
    // verificationMethod.type,
    verificationMethod.id,
    verificationMethod.controller,
    expires,
    revoked,
  )

  const innerImport = (jwk: JWK, flag: Flag) => {
    let convertedJwk: JWKEC
    try {
      convertedJwk = jwk as JWKEC
    } catch (error) {
      throw new ImplementationError(
        ImplementationErrorCode.INVALID_KEYPAIR_CONTENT,
        "keypair/core#jwkToKeypair",
        `The ${flag} key JWK is not well-formed: ${error}`,
      )
    }
    return jwkToKey(convertedJwk, flag)
  }

  // import the private key if it is presented
  if (verificationMethod.secretKeyJwk) {
    keypair.privateKey = innerImport(verificationMethod.secretKeyJwk, "private")
  }

  // import the public key if it is presented
  if (verificationMethod.publicKeyJwk) {
    keypair.publicKey = innerImport(verificationMethod.publicKeyJwk, "public")
  }

  // both public and private key JWKs are missing
  if (!verificationMethod.secretKeyJwk && !verificationMethod.publicKeyJwk) {
    throw new ImplementationError(
      ImplementationErrorCode.INVALID_KEYPAIR_CONTENT,
      "keypair/core#jwkToKeypair",
      "Both public and private key JWKs are missing from the verification method!",
    )
  }

  return keypair
}

/**
 * Export a BBS keypair instance into a verification method containing a keypair in multibase format.
 *
 * @param {BbsKeypair} keypair An BBS keypair instance.
 * @param {Flag} flag The flag to determine if the key is private or public.
 *
 * @returns {VerificationMethodMultibase} A verification method containing a multibase document.
 */
export function keypairToMultibase(keypair: BbsKeypair, flag: Flag): VerificationMethodMultibase {
  // check the controller and identifier
  if (!keypair.controller || !keypair.id) {
    throw new ImplementationError(
      ImplementationErrorCode.INVALID_KEYPAIR_CONTENT,
      "keypair/core#keypairToMultibase",
      "The keypair should have a controller and an identifier!",
    )
  }

  // prepare the document for export
  const document: VerificationMethodMultibase = {
    id: keypair.id!,
    type: SUITE_CONSTANT.KEYPAIR_DOCUMENT_TYPE_MULTI,
    controller: keypair.controller!,
    expires: keypair.revoked ? format.toW3CTimestamp(keypair.revoked) : undefined,
    revoked: keypair.revoked ? format.toW3CTimestamp(keypair.revoked) : undefined,
  }

  // consider the following 5 cases:
  //
  // 1. The `flag` is `private`, but the private key is missing. Throw an error.
  // 2. The `flag` is `private`, and the public key is missing. Export the private key only.
  // 3. The `flag` is `private`, and the public key is presented. Export the public key and set the `id` accordingly.
  // 4. The `flag` is `public`, but the public key is missing. Throw an error.
  // 5. The `flag` is `public`, and the public key is presented. Export the public key, and set the `id` accordingly.

  if (flag === "private") {
    if (!keypair.privateKey) {
      throw new ImplementationError(
        ImplementationErrorCode.INVALID_KEYPAIR_CONTENT,
        "keypair/core#keypairToMultibase",
        "The private key is missing from the keypair!",
      )
    } else {
      document.secretKeyMultibase = materialToMultibase(keypair.privateKey, "private")
    }
  }

  if (keypair.publicKey) {
    document.publicKeyMultibase = materialToMultibase(keypair.publicKey, "public")
  } else if (flag === "public") {
    throw new ImplementationError(
      ImplementationErrorCode.INVALID_KEYPAIR_CONTENT,
      "keypair/core#keypairToMultibase",
      "The public key is missing from the keypair!",
    )
  }

  return document
}

/**
 * Import a keypair from a serialized verification method containing a keypair in multibase format.
 *
 * @param {VerificationMethodMultibase} document A verification method fetched from an external source.
 * @param {Date} [expires] The expiration date of the keypair.
 * @param {Date} [revoked] The revoked date of the keypair.
 *
 * @returns {BbsKeypair} A BBS keypair instance.
 */
export function multibaseToKeypair(
  verificationMethod: VerificationMethodMultibase,
  expires?: Date,
  revoked?: Date,
): BbsKeypair {
  const keypair = new BbsKeypair(verificationMethod.id, verificationMethod.controller, expires, revoked)

  // import the private key if it is presented
  if (verificationMethod.secretKeyMultibase) {
    keypair.privateKey = multibaseToMaterial(verificationMethod.secretKeyMultibase, "private")
  }

  // import the public key if it is presented
  if (verificationMethod.publicKeyMultibase) {
    keypair.publicKey = multibaseToMaterial(verificationMethod.publicKeyMultibase, "public")
  }

  // both public and private key JWKs are missing
  if (!verificationMethod.secretKeyMultibase && !verificationMethod.publicKeyMultibase) {
    throw new ImplementationError(
      ImplementationErrorCode.INVALID_KEYPAIR_CONTENT,
      "keypair/core#multibaseToKeypair",
      "Both public and private key JWKs are missing from the verification method!",
    )
  }

  return keypair
}
