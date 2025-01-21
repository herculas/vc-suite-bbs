/**
 * Transfer a byte array to a hex string.
 *
 * @param {Uint8Array} bytes The byte array to transfer.
 *
 * @returns {string} The hex string.
 */
export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("")
}

/**
 * Transfer a hex string to a byte array.
 *
 * @param {string} hex The hex string to transfer.
 *
 * @returns {Uint8Array} The byte array.
 */
export function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) {
    throw new Error("hex string must have an even number of characters")
  }
  if (hex.length === 0) {
    return new Uint8Array()
  }
  return new Uint8Array(
    hex
      .match(/.{1,2}/g)!
      .map((byte) => parseInt(byte, 16)),
  )
}
