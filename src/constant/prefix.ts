import type { Flag } from "@herculas/vc-data-integrity"

import { Feature } from "./feature.ts"

/**
 * The encoding of an BLS12-381 public key in the G2 group MUST start with the two-byte prefix `0xeb01` (the varint
 * expression of `0xeb`), followed by the 96-byte compressed public key data.
 *
 * The resulting 98-byte value MUST be encoded using the base-58-btc alphabet, and then prepended with the base-58-btc
 * Multibase header `z`.
 *
 * @see https://www.w3.org/TR/cid/#Multikey
 */
const PUBLIC_KEY_MULTIBASE = "eb01"

/**
 * The encoding of an BLS12-381 secret key in the G2 group MUST start with the two-byte prefix `0x8030` (the varint
 * expression of `0x130a`), followed by the 32-byte compressed private key data.
 *
 * The resulting 34-byte value MUST be encoded using the base-58-btc alphabet, and then prepended with the base-58-btc
 * Multibase header `z`.
 *
 * @see https://www.w3.org/TR/cid/#Multikey
 */
const PRIVATE_KEY_MULTIBASE = "8030"

export const MULTIBASE: Map<Flag, string> = new Map([
  ["public", PUBLIC_KEY_MULTIBASE],
  ["private", PRIVATE_KEY_MULTIBASE],
])

/**
 * The prefix `c14n` is used to indicate that the following characters are a base-10 integer.
 */
export const BLANK_LABEL = "c14n"

/**
 * The prefix of the value of entries in a compressed label map.
 */
export const COMPRESSED_VALUE = "b"

/**
 * The header of the BBS base proof.
 */
export const CBOR_BASE: Map<Feature, string> = new Map([
  [Feature.BASELINE, "d95d02"],
  [Feature.ANONYMOUS_HOLDER_BINDING, "d95d04"],
  [Feature.PSEUDONYM, "d95d06"],
  [Feature.HOLDER_BINDING_PSEUDONYM, "d95d08"],
])

/**
 * The header of the BBS derived selective proof.
 */
export const CBOR_DERIVED: Map<Feature, string> = new Map([
  [Feature.BASELINE, "d95d03"],
  [Feature.ANONYMOUS_HOLDER_BINDING, "d95d05"],
  [Feature.PSEUDONYM, "d95d07"],
  [Feature.HOLDER_BINDING_PSEUDONYM, "d95d09"],
])
