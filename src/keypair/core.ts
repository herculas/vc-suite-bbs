import { concatenate } from "@crumble-jon/ld-crypto-syntax"
import { generateKeypair as keygen } from "@crumble-jon/bbs-signature"
import { base58 } from "@scure/base"

import { bytesToHex, hexToBytes } from "../utils/format.ts"
import * as KEYPAIR_CONSTANT from "./constants.ts"

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
