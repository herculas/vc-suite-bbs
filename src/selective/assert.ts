import { assert } from "@std/assert"

import { isNaturalNumber, isString, isUint8Array } from "../utils/guard.ts"

import type { BaseProofValue, CompressedProofValue } from "./types.ts"

export function assertBaseProofValue(components: unknown): Omit<BaseProofValue, "feature"> {
  assert(Array.isArray(components) && (components.length === 5 || components.length === 6))

  assert(isUint8Array(components[0], 80)) // bbsSignature
  assert(isUint8Array(components[1], 64)) // bbsHeader
  assert(isUint8Array(components[2], 96)) // publicKey
  assert(isUint8Array(components[3], 32)) // hmacKey
  assert(Array.isArray(components[4]) && components[4].every(isString)) // mandatoryPointers

  const result: Omit<BaseProofValue, "feature"> = {
    bbsSignature: components[0],
    bbsHeader: components[1],
    publicKey: components[2],
    hmacKey: components[3],
    mandatoryPointers: components[4],
  }

  // TODO: the length of signerNymEntropy
  if (components.length === 6) {
    assert(isUint8Array(components[5])) // signerNymEntropy
    result.signerNymEntropy = components[5]
  }

  return result
}

export function assertCompressedProofValue(components: unknown): Omit<CompressedProofValue, "feature"> {
  assert(Array.isArray(components) && (components.length === 5 || components.length === 6 || components.length === 8))

  assert(isUint8Array(components[0])) // bbsProof
  assert(
    components[1] instanceof Map &&
      components[1].entries().every(([key, value]) => Number.isInteger(key) && Number.isInteger(value)),
  ) // labelMap
  assert(Array.isArray(components[2]) && components[2].every(isNaturalNumber)) // mandatoryIndexes
  assert(Array.isArray(components[3]) && components[3].every(isNaturalNumber)) // selectiveIndexes
  assert(isUint8Array(components[4])) // presentationHeader

  const result: Omit<CompressedProofValue, "feature"> = {
    bbsProof: components[0],
    compressedLabelMap: components[1],
    mandatoryIndexes: components[2],
    selectiveIndexes: components[3],
    presentationHeader: components[4],
  }

  if (components.length === 6) {
    assert(isNaturalNumber(components[5])) // lengthBBSMessages
    result.lengthBBSMessages = components[5]
  }

  // TODO: the length of nymDomain and pseudonym
  if (components.length === 8) {
    assert(isUint8Array(components[5])) // nymDomain
    assert(isUint8Array(components[6])) // pseudonym
    assert(isNaturalNumber(components[7])) // lengthBBSMessages
    result.nymDomain = components[5]
    result.pseudonym = components[6]
    result.lengthBBSMessages = components[7]
  }

  return result
}
