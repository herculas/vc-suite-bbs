import {
  base58btc,
  base64url,
  format,
  ImplementationError,
  ImplementationErrorCode,
  type JWK,
  type JWKEC,
  type KeypairOptions,
} from "@herculas/vc-data-integrity"
import { Cipher, key } from "@herculas/bbs-signature"

import { bytesToHex, hexToBytes } from "../utils/format.ts"

import * as PREFIX_CONSTANT from "../constant/prefix.ts"
import * as SUITE_CONSTANT from "../constant/suite.ts"

/**
 * Generate a BLS12-381 keypair for BBS signatures.
 *
 * @param {Uint8Array} [seed] The seed to use for keypair generation.
 * @param {Cipher} [cipher] The cipher suite to be used.
 *
 * @returns {object} The BLS12-381 keypair, containing a secret key and a public key in Uint8Array format.
 */
export function generateKeypair(
  seed?: Uint8Array,
  cipher: Cipher = Cipher.XOF_SHAKE_256,
): {
  secretKey: Uint8Array
  publicKey: Uint8Array
} {
  if (!seed) {
    seed = new Uint8Array(SUITE_CONSTANT.DEFAULT_KEY_MATERIAL_LENGTH)
    crypto.getRandomValues(seed)
  }
  const material = bytesToHex(seed)
  const { secretKey, publicKey } = key.createPair(material, undefined, undefined, cipher)
  return {
    secretKey: hexToBytes(secretKey),
    publicKey: hexToBytes(publicKey),
  }
}

/**
 * Encode a key material into a multibase-encoded string.
 *
 * @param {Uint8Array} material The key material in Uint8Array format.
 * @param {KeypairOptions.Flag} flag The flag to determine if the key is private or public.
 *
 * @returns {string} The multibase-encoded key string.
 */
export function materialToMultibase(material: Uint8Array, flag: KeypairOptions.Flag): string {
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
  return base58btc.encode(multibase)
}

/**
 * Decode a multibase encoded private or public key into a Uint8Array key material, and check the key material against
 * the prefix from the specification.
 *
 * @param {string} multibase A multibase-encoded private or public key string.
 * @param {KeypairOptions.Flag} flag The flag to determine if the key is private or public.
 *
 * @returns {Uint8Array} The decoded key material in Uint8Array format.
 */
export function multibaseToMaterial(multibase: string, flag: KeypairOptions.Flag): Uint8Array {
  const key = base58btc.decode(multibase)
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
  return base64url.encode(new Uint8Array(hash))
}

/**
 * Convert a key material into a `JWKEC` object. The flag determines if the key is private or public. When the key is
 * private, the `d` field is included in the resulted object.
 *
 * @param {Uint8Array} material A BBS private key or public key material.
 * @param {KeypairOptions.Flag} flag The flag to determine if the key is private or public.
 *
 * @returns {JWKEC} An object representing a JSON Web Key.
 */
export function keyToJwk(material: Uint8Array, flag: KeypairOptions.Flag): JWKEC {
  const expectedLength = flag === "private" ? SUITE_CONSTANT.PRIVATE_KEY_LENGTH : SUITE_CONSTANT.PUBLIC_KEY_LENGTH
  const usage = flag === "private" ? ["sign"] : ["verify"]

  if (material.length !== expectedLength) {
    throw new ImplementationError(
      ImplementationErrorCode.INVALID_KEYPAIR_LENGTH,
      "keypair/core#materialToMultibase",
      `The ${flag} key material should be a ${expectedLength}-octet array!`,
    )
  }

  // TODO: encoding in JWK
  const serialized = base64url.encode(material)

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
 * @param {KeypairOptions.Flag} flag The flag to determine if the key is private or public.
 *
 * @returns {Uint8Array} The key material in Uint8Array format.
 */
export function jwkToKey(jwk: JWKEC, flag: KeypairOptions.Flag): Uint8Array {
  if ((flag === "private" && !jwk.d) || (flag === "public" && jwk.x === "")) {
    throw new ImplementationError(
      ImplementationErrorCode.INVALID_KEYPAIR_CONTENT,
      "keypair/core#jwkToKey",
      `The provided ${flag} key object does not contain the required field!`,
    )
  }

  // TODO: decoding in JWK
  const serialized = flag === "public" ? jwk.x : jwk.d!
  return base64url.decode(serialized)
}

// /**
//  * Export a keypair instance into a `KeypairDocument` object containing a keypair in JWK format.
//  *
//  * @param {BBSKeypair} keypair A BBS keypair instance.
//  * @param {Flag} flag The flag to determine if the key is private or public.
//  *
//  * @returns {Promise<KeypairDocument>} A serialized keypair to be exported.
//  */
// export async function keypairToJwk(keypair: BBSKeypair, flag: Flag): Promise<KeypairDocument> {
//   const document: KeypairDocument = {
//     "@context": CONTEXT_URL.JWS_2020,
//     id: keypair.id!,
//     controller: keypair.controller!,
//     type: KEYPAIR_CONSTANT.JWK_TYPE,
//     revoked: keypair.revoked ? toW3CTimestampString(keypair.revoked) : undefined,
//   }

//   if (flag === "public") {
//     document.publicKeyJwk = keyToJwk(keypair, "public")
//     document.id = `${keypair.controller!}#${await getJwkThumbprint(document.publicKeyJwk!)}`
//   } else {
//     document.privateKeyJwk = keyToJwk(keypair, "private")
//     document.id = `${keypair.controller!}#${await getJwkThumbprint(document.privateKeyJwk!)}`
//   }
//   return document
// }

// /**
//  * Import a keypair from a serialized `KeypairDocument` object containing a keypair in JWK format.
//  *
//  * @param {KeypairDocument} document An externally fetched key document.
//  * @param {Date} revoked The revoked date of the keypair.
//  *
//  * @returns {Promise<Ed25519Keypair>} Resolve to a keypair instance.
//  */
// export function jwkToKeypair(document: KeypairDocument, revoked?: Date): BBSKeypair {
//   const keypair = new BBSKeypair(document.type as Algorithm, document.id, document.controller, revoked)

//   // TODO: encapsulated error
//   if (document.privateKeyJwk) {
//     // private key
//     const jwk = document.privateKeyJwk as JWKEC
//     keypair.privateKey = jwkToKey(jwk, "private").privateKey
//     keypair.publicKey = jwkToKey(jwk, "public").publicKey
//   } else if (document.publicKeyJwk) {
//     // public key only
//     const jwk = document.publicKeyJwk as JWKEC
//     keypair.publicKey = jwkToKey(jwk, "public").publicKey
//   } else {
//     throw new Error("Invalid JWK keypair")
//   }

//   return keypair
// }

// /**
//  * Export a keypair instance into a `KeypairDocument` object containing a keypair in multibase format.
//  *
//  * @param {BBSKeypair} keypair An BBS keypair instance.
//  * @param {Flag} flag The flag to determine if the key is private or public.
//  *
//  * @returns {Promise<KeypairDocument>} Resolve to a `KeypairDocument` object.
//  */
// export function keypairToMultibase(keypair: BBSKeypair, flag: Flag): KeypairDocument {
//   // TODO: context
//   const document: KeypairDocument = {
//     "@context": CONTEXT_URL.JWS_2020,
//     id: keypair.id!,
//     controller: keypair.controller!,
//     type: keypair.type,
//     revoked: keypair.revoked ? toW3CTimestampString(keypair.revoked) : undefined,
//   }

//   if (flag === "public") {
//     document.publicKeyMultibase = keypair.getPublicKeyMultibase()
//   } else {
//     document.privateKeyMultibase = keypair.getPrivateKeyMultibase()
//   }
//   return document
// }

// /**
//  * Import a keypair from a serialized `KeypairDocument` object containing a keypair in multibase format.
//  *
//  * @param {KeypairDocument} document An externally fetched key document.
//  * @param {Date} revoked The revoked date of the keypair.
//  *
//  * @returns {BBSKeypair} Resolve to a keypair instance.
//  */
// export function multibaseToKeypair(document: KeypairDocument, revoked?: Date): BBSKeypair {
//   const keypair = new BBSKeypair(document.type as Algorithm, document.id, document.controller, revoked)

//   if (document.secretKeyMultibase) {
//     keypair.privateKey = multibaseToMaterial(document.secretKeyMultibase, "private")
//   } else if (document.publicKeyMultibase) {
//     keypair.publicKey = multibaseToMaterial(document.publicKeyMultibase, "public")
//   } else {
//     // TODO: encapsulated error
//     throw new Error("Invalid multibase keypair")
//   }

//   return keypair
// }
