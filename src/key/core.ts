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

import { Bls12381G2Keypair } from "./keypair.ts"

import * as PREFIX_CONSTANT from "../constant/prefix.ts"
import * as SUITE_CONSTANT from "../constant/suite.ts"

/**
 * Generate a BLS12-381 G2 keypair for BBS signatures.
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
    seed = new Uint8Array(SUITE_CONSTANT.MINIMAL_SEED_LENGTH)
    crypto.getRandomValues(seed)
  }

  if (seed.length < SUITE_CONSTANT.MINIMAL_SEED_LENGTH) {
    throw new ImplementationError(
      ImplementationErrorCode.INVALID_KEYPAIR_LENGTH,
      "key/core#generateKeypair",
      "The seed should be at least 32-octet long!",
    )
  }

  const material = format.bytesToHex(seed)
  const { secretKey, publicKey } = key.createPair(material)
  return {
    secretKey: format.hexToBytes(secretKey),
    publicKey: format.hexToBytes(publicKey),
  }
}

/**
 * Calculate the thumbprint of a `JWK` instance using SHA-256 hashing algorithm.
 *
 * @param {JWK} jwk A JSON Web Key instance.
 *
 * @returns {Promise<string>} Resolve to the thumbprint of the `JWK` instance.
 */
async function getJwkThumbprint(jwk: JWK): Promise<string> {
  const data = new TextEncoder().encode(JSON.stringify(jwk))
  const hash = await crypto.subtle.digest("SHA-256", data)
  return multi.base64url.encode(new Uint8Array(hash))
}

/**
 * Export a BLS raw keypair instance to a verification method document. The key is stored in the exported document in
 * either `JsonWebKey` or `Multikey` format, specified by the `type` field in the document. The `JsonWebKey` or
 * `Multikey` generated from the above process will ultimately be wrapped into a verification method document, along
 * with other metadata associated with that key, such as the controller, the identifier, and expiration date.
 *
 * The flowchart below briefly illustrates this export process:
 *
 *            materialToMultibase                         keypairToMultibase
 *     ┌─────────────────────────────> Multibase Key ───────────────────────────────┐
 *     │                           (base-58-btc string)                             │
 * Key Material                                                            Verification Method
 *     │        materialToJwk                                keypairToJwk           │
 *     └─────────────────────────────> JSON Web Key ────────────────────────────────┘
 *                                       (JWKEC)
 */

/**
 * Encode a BLS12-381 G2 key material into a multibase-encoded string.
 *
 * @param {Uint8Array} material The key material in Uint8Array format.
 * @param {Flag} flag The flag to determine if the key is private or public.
 *
 * @returns {string} The multibase-encoded key string.
 */
export function materialToMultibase(material: Uint8Array, flag: Flag): string {
  const multibasePrefixHex = PREFIX_CONSTANT.MULTIBASE.get(flag)
  const materialLength = SUITE_CONSTANT.KEY_MATERIAL_LENGTH.get(flag)

  if (!multibasePrefixHex || !materialLength) {
    throw new ImplementationError(
      ImplementationErrorCode.INVALID_KEYPAIR_CONTENT,
      "keypair/core#materialToMultibase",
      `This suite does not support ${flag} key!`,
    )
  }

  if (material.length !== materialLength) {
    throw new ImplementationError(
      ImplementationErrorCode.INVALID_KEYPAIR_LENGTH,
      "keypair/core#materialToMultibase",
      `The ${flag} key material should be a ${materialLength}-octet array!`,
    )
  }

  const multibasePrefix = format.hexToBytes(multibasePrefixHex)
  const multibaseMaterial = format.concatenate(multibasePrefix, material)
  return multi.base58btc.encode(multibaseMaterial)
}

/**
 * Export a BLS12-381 G2 keypair instance into a verification method containing a keypair in multibase format.
 *
 * @param {Bls12381G2Keypair} keypair An BLS12-381 G2 keypair instance.
 * @param {Flag} flag The flag to determine if the key is private or public.
 *
 * @returns {VerificationMethodMultibase} A verification method containing a multibase key.
 */
export function keypairToMultibase(keypair: Bls12381G2Keypair, flag: Flag): VerificationMethodMultibase {
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
 * Convert a key material into a `JWKEC` object. The flag determines if the key is private or public. When the key is
 * private, the `d` field is included in the resulted object.
 *
 * @param {Uint8Array} material A BLS12-381 private key or G2 public key material.
 * @param {Flag} flag The flag to determine if the key is private or public.
 *
 * @returns {JWKEC} An `JWKEC` object representing a JSON Web Key.ƒ
 */
export function materialToJwk(material: Uint8Array, flag: Flag): JWKEC {
  const materialLength = SUITE_CONSTANT.KEY_MATERIAL_LENGTH.get(flag)

  if (material.length !== materialLength) {
    throw new ImplementationError(
      ImplementationErrorCode.INVALID_KEYPAIR_LENGTH,
      "keypair/core#keyToJwk",
      `The ${flag} key material should be a ${materialLength}-octet array!`,
    )
  }

  const serialized = multi.base64url.encode(material)

  const jwk: JWKEC = {
    kty: SUITE_CONSTANT.JWK_TYPE,
    use: SUITE_CONSTANT.JWK_USE,
    key_ops: flag === "private" ? ["sign"] : ["verify"],
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
 * Export a BLS12-381 G2 keypair instance into a verification method containing a keypair in `JWK` format.
 *
 * @param {Bls12381G2Keypair} keypair A BLS12-381 G2 keypair instance.
 * @param {Flag} flag The flag to determine if the key is private or public.
 *
 * @returns {Promise<VerificationMethodJwk>} Resolve to a verification method containing a JSON Web Key.
 */
export async function keypairToJwk(keypair: Bls12381G2Keypair, flag: Flag): Promise<VerificationMethodJwk> {
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
      document.secretKeyJwk = materialToJwk(keypair.privateKey, "private")
    }
  }

  if (keypair.publicKey) {
    document.publicKeyJwk = materialToJwk(keypair.publicKey, "public")
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
 * Import a verification method document into BLS12-381 key material. The keypair is stored in the verification method
 * document in either `JsonWebKey` or `Multikey` format, as specified by the `type` field in the document.
 *
 * The flowchart below briefly illustrates this export process:
 *
 *                multibaseToKeypair                         multibaseToMaterial
 *         ┌─────────────────────────────> Multibase Key ───────────────────────────────┐
 *         │                           (base-58-btc string)                             │
 * Verification Method                                                           Key Material
 *         │        jwkToKeypair                                jwkToMaterial           │
 *         └─────────────────────────────> JSON Web Key ────────────────────────────────┘
 *                                           (JWKEC)
 */

/**
 * Import a BLS12-381 G2 keypair from a serialized verification method containing a keypair in `Multikey` format.
 *
 * @param {VerificationMethodMultibase} verificationMethod A verification method fetched from an external source.
 * @param {Date} [expires] The expiration date of the keypair.
 * @param {Date} [revoked] The revoked date of the keypair.
 *
 * @returns {Bls12381G2Keypair} A BLS12-381 G2 keypair instance.
 */
export function multibaseToKeypair(
  verificationMethod: VerificationMethodMultibase,
  expires?: Date,
  revoked?: Date,
): Bls12381G2Keypair {
  const keypair = new Bls12381G2Keypair(verificationMethod.id, verificationMethod.controller, expires, revoked)

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

/**
 * Decode a multibase encoded private or public key into an `Uint8Array` key material, and check the key material
 * against the prefix according to the specification.
 *
 * @param {string} multibase A multibase-encoded private or public key string.
 * @param {Flag} flag The flag to determine if the key is private or public.
 *
 * @returns {Uint8Array} The decoded key material in `Uint8Array` format.
 */
export function multibaseToMaterial(multibase: string, flag: Flag): Uint8Array {
  const multibaseMaterial = multi.base58btc.decode(multibase)
  const multibasePrefixHex = PREFIX_CONSTANT.MULTIBASE.get(flag)
  const materialLength = SUITE_CONSTANT.KEY_MATERIAL_LENGTH.get(flag)

  if (!multibasePrefixHex || !materialLength) {
    throw new ImplementationError(
      ImplementationErrorCode.INVALID_KEYPAIR_CONTENT,
      "keypair/core#multibaseToMaterial",
      `This suite does not support ${flag} key!`,
    )
  }

  const multibasePrefix = format.hexToBytes(multibasePrefixHex)
  if (!multibasePrefix.every((value, index) => multibaseMaterial[index] === value)) {
    throw new ImplementationError(
      ImplementationErrorCode.DECODING_ERROR,
      "keypair/core#multibaseToMaterial",
      `The provided ${flag} key multibase ${multibase} does not match the specified prefix!`,
    )
  }

  const material = multibaseMaterial.slice(multibasePrefix.length)
  if (material.length !== materialLength) {
    throw new ImplementationError(
      ImplementationErrorCode.INVALID_KEYPAIR_LENGTH,
      "keypair/core#multibaseToMaterial",
      `The ${flag} key material should be a ${materialLength}-octet array!`,
    )
  }

  return material
}

/**
 * Import a BLS12-381 G2 keypair from a serialized verification method containing a keypair in `JWK` format.
 *
 * @param {VerificationMethodJwk} verificationMethod A verification method fetched from an external source.
 * @param {Date} [expires] The expiration date of the keypair.
 * @param {Date} [revoked] The revoked date of the keypair.
 *
 * @returns {Promise<Bls12381G2Keypair>} Resolve to a BLS12-381 G2 keypair instance.
 */
export function jwkToKeypair(
  verificationMethod: VerificationMethodJwk,
  expires?: Date,
  revoked?: Date,
): Bls12381G2Keypair {
  const keypair = new Bls12381G2Keypair(verificationMethod.id, verificationMethod.controller, expires, revoked)

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
    return jwkToMaterial(convertedJwk, flag)
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
 * Convert a `JWKEC` key object into a key material. The flag determines if the key is private or public. When the key
 * is private, the `d` field MUST be provided in the `jwk` input.
 *
 * @param {JWKEC} jwk An object representing a JSON Web Key.
 * @param {Flag} flag The flag to determine if the key is private or public.
 *
 * @returns {Uint8Array} The key material in `Uint8Array` format.
 */
export function jwkToMaterial(jwk: JWKEC, flag: Flag): Uint8Array {
  const materialLength = SUITE_CONSTANT.KEY_MATERIAL_LENGTH.get(flag)
  if (!materialLength) {
    throw new ImplementationError(
      ImplementationErrorCode.INVALID_KEYPAIR_CONTENT,
      "keypair/core#jwkToMaterial",
      `This suite does not support ${flag} key!`,
    )
  }

  // check the key type `kty` and usage `use`
  if (jwk.kty !== SUITE_CONSTANT.JWK_TYPE || jwk.use !== SUITE_CONSTANT.JWK_USE) {
    throw new ImplementationError(
      ImplementationErrorCode.INVALID_KEYPAIR_CONTENT,
      "keypair/core#jwkToMaterial",
      `The provided ${flag} key object does not match the required key type or usage!`,
    )
  }

  // check the key algorithm `alg` and curve `crv`
  if (jwk.alg !== SUITE_CONSTANT.ALGORITHM || jwk.crv !== SUITE_CONSTANT.ALGORITHM) {
    throw new ImplementationError(
      ImplementationErrorCode.INVALID_KEYPAIR_CONTENT,
      "keypair/core#jwkToMaterial",
      `The provided ${flag} key object does not match the required algorithm!`,
    )
  }

  // Check the key operations and required fields based on key type
  const expectedOp = flag === "public" ? "verify" : "sign"
  const requiredField = flag === "public" ? "x" : "d"
  const fieldValue = flag === "public" ? jwk.x : jwk.d

  // Validate key operations
  if (!jwk.key_ops?.includes(expectedOp) || jwk.key_ops.length !== 1) {
    throw new ImplementationError(
      ImplementationErrorCode.INVALID_KEYPAIR_CONTENT,
      "keypair/core#jwkToMaterial",
      `The ${flag} key object must have exactly one "key_ops" value of "${expectedOp}"!`,
    )
  }

  // Validate required field presence
  if (!fieldValue || fieldValue === "") {
    throw new ImplementationError(
      ImplementationErrorCode.INVALID_KEYPAIR_CONTENT,
      "keypair/core#jwkToMaterial",
      `The ${flag} key requires the "${requiredField}" field!`,
    )
  }

  // Decode and validate material length
  const material = multi.base64url.decode(fieldValue)
  if (material.length !== materialLength) {
    throw new ImplementationError(
      ImplementationErrorCode.INVALID_KEYPAIR_LENGTH,
      "keypair/core#jwkToMaterial",
      `The ${flag} key material should be a ${materialLength}-octet array!`,
    )
  }

  return material
}
