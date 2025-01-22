import { concatenate, JWK, JWKEC, KeypairDocument, toW3CTimestampString } from "@crumble-jon/ld-crypto-syntax"
import { generateKeypair as keygen } from "@crumble-jon/bbs-signature"
import { base58, base64url } from "@scure/base"

import * as CONTEXT_URL from "../context/constants.ts"
import * as KEYPAIR_CONSTANT from "./constants.ts"
import { bytesToHex, hexToBytes } from "../utils/format.ts"
import { BBSKeypair } from "./keypair.ts"

type Flag = "private" | "public"
export type Algorithm = "BLS12_381_G1_XOF_SHAKE_256" | "BLS12_381_G1_XMD_SHA_256"

/**
 * Generate a BLS12-381 keypair for BBS signatures.
 *
 * @param {Uint8Array} [seed] The seed to use for keypair generation.
 *
 * @returns {secretKey: Uint8Array, publicKey: Uint8Array} The BLS12-381 keypair.
 */
export function generateKeypair(
  algorithm: Algorithm,
  seed?: Uint8Array,
): { secretKey: Uint8Array; publicKey: Uint8Array } {
  if (!seed) {
    seed = new Uint8Array(32)
    crypto.getRandomValues(seed)
  }
  const material = bytesToHex(seed)
  const { secretKey, publicKey } = keygen(material, undefined, undefined, algorithm)
  return {
    secretKey: hexToBytes(secretKey),
    publicKey: hexToBytes(publicKey),
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
  // TODO: magic number
  // TODO: throw encapsulated error
  if (flag === "private" && material.length !== 32) {
    throw new Error("Invalid private key length")
  }
  if (flag === "public" && material.length !== 96) {
    throw new Error("Invalid public key length")
  }

  const multiPrefix = flag === "private"
    ? KEYPAIR_CONSTANT.MULTIBASE_PRIVATE_PREFIX
    : KEYPAIR_CONSTANT.MULTIBASE_PUBLIC_PREFIX

  const multibase = concatenate(multiPrefix, material)
  return KEYPAIR_CONSTANT.MULTIBASE_BASE58_BTC_PREFIX + base58.encode(multibase)
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
  // TODO: throw encapsulated error
  if (!multibase.startsWith(KEYPAIR_CONSTANT.MULTIBASE_BASE58_BTC_PREFIX)) {
    throw new Error("Invalid multibase prefix")
  }
  const key = base58.decode(multibase.slice(KEYPAIR_CONSTANT.MULTIBASE_BASE58_BTC_PREFIX.length))
  const prefix = flag === "private"
    ? KEYPAIR_CONSTANT.MULTIBASE_PRIVATE_PREFIX
    : KEYPAIR_CONSTANT.MULTIBASE_PUBLIC_PREFIX
  prefix.forEach((value, index) => {
    if (key[index] !== value) {
      throw new Error("Invalid multibase prefix")
    }
  })
  return key.slice(prefix.length)
}

/**
 * Convert a key material into a `JWKEC` object. The flag determines if the key is private or public. When the key is
 * private, the `d` field is included in the resulted object.
 *
 * @param {Object} keypair A BBS keypair instance.
 * @param {Flag} flag The flag to determine if the key is private or public.
 *
 * @returns {JWKEC} An object representing a JSON Web Key.
 */
export function keyToJwk(
  keypair: { type: string; publicKey?: Uint8Array; privateKey?: Uint8Array },
  flag: Flag,
): JWKEC {
  // TODO: encapsulated error
  if (flag === "private" && !keypair.privateKey) {
    throw new Error("Private key not set")
  }

  if (flag === "public" && !keypair.publicKey) {
    throw new Error("Public key not set")
  }

  const jwk: JWKEC = {
    kty: KEYPAIR_CONSTANT.JWK_TYPE,
    use: KEYPAIR_CONSTANT.JWK_USE,
    key_ops: flag === "private" ? ["sign"] : ["verify"],
    alg: keypair.type,
    ext: true,
    crv: KEYPAIR_CONSTANT.JWK_CURVE,
    x: keypair.publicKey ? base64url.encode(keypair.publicKey) : "",
    y: "",
    d: flag === "private" ? base64url.encode(keypair.privateKey!) : undefined,
  }

  return jwk
}

export function jwkToKey(jwk: JWKEC, flag: Flag): { publicKey?: Uint8Array; privateKey?: Uint8Array } {
  // TODO: encapsulated error
  if (flag === "private" && !jwk.d) {
    throw new Error("Private key not set")
  }

  if (flag === "public" && jwk.x === "") {
    throw new Error("Public key not set")
  }

  return {
    publicKey: jwk.x === "" ? undefined : base64url.decode(jwk.x),
    privateKey: flag === "private" ? base64url.decode(jwk.d!) : undefined,
  }
}

/**
 * Export a keypair instance into a `KeypairDocument` object containing a keypair in JWK format.
 *
 * @param {BBSKeypair} keypair A BBS keypair instance.
 * @param {Flag} flag The flag to determine if the key is private or public.
 *
 * @returns {Promise<KeypairDocument>} A serialized keypair to be exported.
 */
export async function keypairToJwk(keypair: BBSKeypair, flag: Flag): Promise<KeypairDocument> {
  const document: KeypairDocument = {
    "@context": CONTEXT_URL.JWS_2020,
    id: keypair.id!,
    controller: keypair.controller!,
    type: KEYPAIR_CONSTANT.JWK_TYPE,
    revoked: keypair.revoked ? toW3CTimestampString(keypair.revoked) : undefined,
  }

  if (flag === "public") {
    document.publicKeyJwk = keyToJwk(keypair, "public")
    document.id = `${keypair.controller!}#${await getJwkThumbprint(document.publicKeyJwk!)}`
  } else {
    document.privateKeyJwk = keyToJwk(keypair, "private")
    document.id = `${keypair.controller!}#${await getJwkThumbprint(document.privateKeyJwk!)}`
  }
  return document
}

/**
 * Import a keypair from a serialized `KeypairDocument` object containing a keypair in JWK format.
 *
 * @param {KeypairDocument} document An externally fetched key document.
 * @param {Date} revoked The revoked date of the keypair.
 *
 * @returns {Promise<Ed25519Keypair>} Resolve to a keypair instance.
 */
export function jwkToKeypair(document: KeypairDocument, revoked?: Date): BBSKeypair {
  const keypair = new BBSKeypair(document.type as Algorithm, document.id, document.controller, revoked)

  // TODO: encapsulated error
  if (document.privateKeyJwk) {
    // private key
    const jwk = document.privateKeyJwk as JWKEC
    keypair.privateKey = jwkToKey(jwk, "private").privateKey
    keypair.publicKey = jwkToKey(jwk, "public").publicKey
  } else if (document.publicKeyJwk) {
    // public key only
    const jwk = document.publicKeyJwk as JWKEC
    keypair.publicKey = jwkToKey(jwk, "public").publicKey
  } else {
    throw new Error("Invalid JWK keypair")
  }

  return keypair
}

/**
 * Export a keypair instance into a `KeypairDocument` object containing a keypair in multibase format.
 *
 * @param {BBSKeypair} keypair An BBS keypair instance.
 * @param {Flag} flag The flag to determine if the key is private or public.
 *
 * @returns {Promise<KeypairDocument>} Resolve to a `KeypairDocument` object.
 */
export function keypairToMultibase(keypair: BBSKeypair, flag: Flag): KeypairDocument {
  // TODO: context
  const document: KeypairDocument = {
    "@context": CONTEXT_URL.JWS_2020,
    id: keypair.id!,
    controller: keypair.controller!,
    type: keypair.type,
    revoked: keypair.revoked ? toW3CTimestampString(keypair.revoked) : undefined,
  }

  if (flag === "public") {
    document.publicKeyMultibase = keypair.getPublicKeyMultibase()
  } else {
    document.privateKeyMultibase = keypair.getPrivateKeyMultibase()
  }
  return document
}

/**
 * Import a keypair from a serialized `KeypairDocument` object containing a keypair in multibase format.
 *
 * @param {KeypairDocument} document An externally fetched key document.
 * @param {Date} revoked The revoked date of the keypair.
 *
 * @returns {BBSKeypair} Resolve to a keypair instance.
 */
export function multibaseToKeypair(document: KeypairDocument, revoked?: Date): BBSKeypair {
  const keypair = new BBSKeypair(document.type as Algorithm, document.id, document.controller, revoked)

  if (document.secretKeyMultibase) {
    keypair.privateKey = multibaseToMaterial(document.secretKeyMultibase, "private")
  } else if (document.publicKeyMultibase) {
    keypair.publicKey = multibaseToMaterial(document.publicKeyMultibase, "public")
  } else {
    // TODO: encapsulated error
    throw new Error("Invalid multibase keypair")
  }

  return keypair
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
  const digest = await crypto.subtle.digest("SHA-256", data)
  return base64url.encode(new Uint8Array(digest))
}
