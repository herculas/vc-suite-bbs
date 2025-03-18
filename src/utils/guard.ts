export function isUint8Array(value: unknown, length?: number): value is Uint8Array {
  return (value instanceof Uint8Array) && (length === undefined || value.length === length)
}

export function isString(value: unknown): value is string {
  return typeof value === "string"
}

export function isNaturalNumber(value: unknown): value is number {
  return typeof value === "number" && Number.isInteger(value) && value >= 0
}
