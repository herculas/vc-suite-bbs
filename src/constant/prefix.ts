import type { Flag } from "@herculas/vc-data-integrity"

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
