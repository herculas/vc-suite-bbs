import * as cbor from "cbor2"
import { format, multi, ProcessingError, ProcessingErrorCode } from "@herculas/vc-data-integrity"

import { assertBaseProofValue, assertCompressedProofValue } from "./assert.ts"
import { compressLabelMap, decompressLabelMap } from "./label.ts"
import { Feature } from "../constant/feature.ts"

import type { BaseProofValue, DerivedProofValue } from "./types.ts"

import * as PREFIX_CONSTANT from "../constant/prefix.ts"

/**
 * Serialize the base proof value, including the BBS signature, HMAC key, and mandatory pointers.
 *
 * @param {BaseProofValue} proofValue proofValue A single object containing six (or seven) components using the names
 * `bbsSignature`, `bbsHeader`, `publicKey`, an HMAC key `hmacKey`, an array of `mandatoryPointers`, `featureOption`,
 * and, depending on the `featureOption` value, possibly a `signer_nym_entropy` value.
 *
 * @returns {string} A serialized base proof value.
 *
 * @see https://www.w3.org/TR/vc-di-bbs/#serializebaseproofvalue
 */
export function serializeBaseProofValue(proofValue: BaseProofValue): string {
  // Procedure:
  //
  // 1. Depending upon the value of the `featureOption`, set up the `proofValue` as follows.
  // 2. If `featureOption` equals `baseline`:
  //
  //    2.1. Initialize a byte array, `proofValue`, that starts with the BBS base proof header bytes `0xd9`, `0x5d`, and
  //         `0x02`.
  //    2.2. Initialize `components` to an array with five elements containing the values of: `bbsSignature`,
  //         `bbsHeader`, `publicKey`, `hmacKey`, and `mandatoryPointers`.
  //
  // 3. If `featureOption` equals `anonymous_holder_binding`:
  //
  //    3.1. Initialize a byte array, `proofValue`, that starts with the BBS base proof header bytes `0xd9`, `0x5d`, and
  //         `0x04`.
  //    3.2. Initialize `components` to an array with six elements containing the values of: `bbsSignature`,
  //         `bbsHeader`, `publicKey`, `hmacKey`, and `mandatoryPointers`.
  //
  // 4. If `featureOption` equals `pseudonym`:
  //
  //    4.1. Initialize a byte array, `proofValue`, that starts with the BBS base proof header bytes `0xd9`, `0x5d`, and
  //         `0x06`.
  //    4.2. Initialize `components` to an array with six elements containing the values of: `bbsSignature`,
  //         `bbsHeader`, `publicKey`, `hmacKey`, `mandatoryPointers`, and `signer_nym_entropy`.
  //
  // 5. If `featureOption` equals `holder_binding_pseudonym`:
  //
  //    5.1. Initialize a byte array, `proofValue`, that starts with the BBS base proof header bytes `0xd9`, `0x5d`, and
  //         `0x08`.
  //    5.2. Initialize `components` to an array with six elements containing the values of: `bbsSignature`,
  //         `bbsHeader`, `publicKey`, `hmacKey`, `mandatoryPointers`, and `signer_nym_entropy`.
  //
  // 6. CBOR-encode components per [RFC-8949] where CBOR tagging MUST NOT be used on any of the components. Append the
  //    produced encoded value to `proofValue`.
  // 7. Initialize `baseProof` to a string with the multibase-base64url-no-pad-encoding of `proofValue`. That is, return
  //    a string starting with "u" and ending with the base64url-no-pad-encoded value of `proofValue`.
  // 8. Return `baseProof` as base proof.

  const components = [
    proofValue.bbsSignature,
    proofValue.bbsHeader,
    proofValue.publicKey,
    proofValue.hmacKey,
    proofValue.mandatoryPointers,
  ]
  if (proofValue.feature === Feature.PSEUDONYM || proofValue.feature === Feature.HOLDER_BINDING_PSEUDONYM) {
    if (!proofValue.signerNymEntropy) {
      throw new ProcessingError(
        ProcessingErrorCode.PROOF_GENERATION_ERROR,
        "selective/serialize#serializeBaseProofValue",
        "Signer nym entropy is required for pseudonym or holder binding pseudonym feature options",
      )
    }
    components.push(proofValue.signerNymEntropy)
  }
  assertBaseProofValue(components)

  const prefixHex = PREFIX_CONSTANT.CBOR_BASE.get(proofValue.feature)!
  const prefix = format.hexToBytes(prefixHex)
  const proofValueBytes = format.concatenate(prefix, cbor.encode(components))
  const baseProof = multi.base64urlnopad.encode(proofValueBytes)
  return baseProof
}

/**
 * Serialize a derived proof value.
 *
 * @param {DerivedProofValue} proofValue A single object containing six to nine components using the names `bbsProof`,
 * `labelMap`, `mandatoryIndexes`, `selectiveIndexes`, `presentationHeader`, `featureOption`, and, depending on the
 * value of the `featureOption` parameter, `nym_domain`, `pseudonym`, and/or `lengthBBSMessages`.
 *
 * @returns {string} A serialized derived proof value.
 *
 * @see https://www.w3.org/TR/vc-di-bbs/#serializederivedproofvalue
 */
export function serializeDerivedProofValue(proofValue: DerivedProofValue): string {
  // Procedure:
  //
  // 1. Initialize `compressedLabelMap` to the result of calling the `compressLabelMap` function, passing `labelMap` as
  //    the parameter.
  // 2. Depending on the value of `featureOption`, do the following:
  //
  //    2.1. If `featureOption` equals `baseline`:
  //
  //         2.1.1. Initialize `proofValue` to start with the disclosure proof header bytes `0xd9`, `0x5d`, and `0x03`.
  //         2.1.2. Initialize `components` to an array with elements containing the values of `bbsProof`,
  //                `compressedLabelMap`, `mandatoryIndexes`, `selectiveIndexes`, and `presentationHeader`.
  //
  //    2.2. If `featureOption` equals `anonymous_holder_binding`:
  //
  //         2.2.1. Initialize `proofValue` to start with the disclosure proof header bytes `0xd9`, `0x5d`, and `0x05`.
  //         2.2.2. Initialize `components` to an array with elements containing the values of `bbsProof`,
  //                `compressedLabelMap`, `mandatoryIndexes`, `selectiveIndexes`, `presentationHeader`, and
  //                `lengthBBSMessages`.
  //
  //    2.3. If `featureOption` equals `pseudonym`:
  //
  //         2.3.1. Initialize `proofValue` to start with the disclosure proof header bytes `0xd9`, `0x5d`, and `0x07`.
  //         2.3.2. Initialize `components` to an array with elements containing the values of `bbsProof`,
  //                `compressedLabelMap`, `mandatoryIndexes`, `selectiveIndexes`, `presentationHeader`, `nym_domain`,
  //                `pseudonym`, and `lengthBBSMessages`.
  //
  //    2.4. If `featureOption` equals `holder_binding_pseudonym`:
  //
  //         2.4.1. Initialize `proofValue` to start with the disclosure proof header bytes `0xd9`, `0x5d`, and `0x09`.
  //         2.4.2. Initialize `components` to an array with elements containing the values of `bbsProof`,
  //                `compressedLabelMap`, `mandatoryIndexes`, `selectiveIndexes`, `presentationHeader`, `nym_domain`,
  //                `pseudonym`, and `lengthBBSMessages`.
  //
  // 3. CBOR-encode `components` per [RFC-8949] where CBOR tagging MUST NOT be used on any of the components. Append the
  //    produced encoded value to `proofValue`.
  // 4. Return the `derivedProof` as a string with the base64url-no-pad-encoding of `proofValue`. That is, return a
  //    string starting with "u" and ending with the base64url-no-pad-encoded value of `proofValue`.

  const compressedLabelMap = compressLabelMap(proofValue.labelMap)
  const components: unknown[] = [
    proofValue.bbsProof,
    compressedLabelMap,
    proofValue.mandatoryIndexes,
    proofValue.selectiveIndexes,
    proofValue.presentationHeader,
  ]

  if (proofValue.feature === Feature.ANONYMOUS_HOLDER_BINDING) {
    if (!proofValue.lengthBBSMessages) {
      throw new ProcessingError(
        ProcessingErrorCode.PROOF_GENERATION_ERROR,
        "selective/serialize#serializeDerivedProofValue",
        "Length BBS messages is required for anonymous holder binding feature option",
      )
    }
    components.push(proofValue.lengthBBSMessages)
  } else if (proofValue.feature === Feature.PSEUDONYM || proofValue.feature === Feature.HOLDER_BINDING_PSEUDONYM) {
    if (!proofValue.nymDomain || !proofValue.pseudonym || !proofValue.lengthBBSMessages) {
      throw new ProcessingError(
        ProcessingErrorCode.PROOF_GENERATION_ERROR,
        "selective/serialize#serializeDerivedProofValue",
        "Nym domain, pseudonym, and length BBS messages are required for this feature options",
      )
    }
    components.push(proofValue.nymDomain, proofValue.pseudonym, proofValue.lengthBBSMessages)
  }

  assertCompressedProofValue(components)

  const prefixHex = PREFIX_CONSTANT.CBOR_DERIVED.get(proofValue.feature)!
  const prefix = format.hexToBytes(prefixHex)
  const proofValueBytes = format.concatenate(prefix, cbor.encode(components))
  const derivedProof = multi.base64urlnopad.encode(proofValueBytes)
  return derivedProof
}

/**
 * Parse the components of an bbs-2023 selective disclosure base proof value.
 *
 * @param {string} proofValue A proof value encoded as a base64url-no-pad string.
 *
 * @returns {BaseProofValue} A single object of parsed base proof, containing six or seven components, using the names
 * `baseSignature`, `bbsHeader`, `publicKey`, `hmacKey`, `mandatoryPointers`, `featureOption`, and possibly optional
 * feature parameter `signer_nym_entropy`.
 *
 * @see https://www.w3.org/TR/vc-di-bbs/#parsebaseproofvalue
 */
export function parseBaseProofValue(proofValue: string): BaseProofValue {
  // Procedure:
  //
  // 1. If the `proofValue` string does not start with `u`, indicating that it is a multibase-base64url-no-pad-encoded
  //    value, an error MUST be raised and SHOULD convey an error type of `PROOF_VERIFICATION_ERROR`.
  // 2. Initialize `decodedProofValue` to the result of `base64url-no-pad-decoding` the substring that follows the
  //    leading `u` in `proofValue`.
  // 3. Check that the BBS base proof starts with an allowed header value and set the `featureOption` variable as
  //    follows:
  //
  //    3.1. If the `decodedProofValue` starts with the bytes `0xd9`, `0x5d`, and `0x02`, set `featureOption` to
  //         `baseline`.
  //    3.2. If the `decodedProofValue` starts with the bytes `0xd9`, `0x5d`, and `0x04`, set `featureOption` to
  //         `anonymous_holder_binding`.
  //    3.3. If the `decodedProofValue` starts with the bytes `0xd9`, `0x5d`, and `0x06`, set `featureOption` to
  //         `pseudonym`.
  //    3.4. If the `decodedProofValue` starts with the bytes `0xd9`, `0x5d`, and `0x08`, set `featureOption` to
  //         `holder_binding_pseudonym`.
  //    3.5. If the `decodedProofValue` starts with any other three bytes sequence, an error MUST be raised and SHOULD
  //         convey an error type of `PROOF_VERIFICATION_ERROR`.
  //
  // 4. Initialize `components` to an array that is the result of CBOR-decoding the bytes that follow the three-byte
  //    BBS base proof header.
  // 5. Based on the value of `featureOption`, return an object on `components`, as follows:
  //
  //    5.1. If `featureOption` equals `baseline`, set the property names for the object based on `components` to
  //         `bbsSignature`, `bbsHeader`, `publicKey`, `hmacKey`, and `mandatoryPointers`, in that order, and add
  //         `featureOption` as a property.
  //    5.2. If `featureOption` equals `anonymous_holder_binding`, set the property names for the object based on
  //         `components` to `bbsSignature`, `bbsHeader`, `publicKey`, `hmacKey`, and `mandatoryPointers`, in that
  //         order, and add `featureOption` as a property.
  //    5.3. If `featureOption` equals `pseudonym`, set the property names for the object based on `components` to
  //         `bbsSignature`, `bbsHeader`, `publicKey`, `hmacKey`, `mandatoryPointers`, and `signer_nym_entropy`, in
  //         that order, and add `featureOption` as a property.
  //    5.4. If `featureOption` equals `holder_binding_pseudonym`, set the property names for the object based on
  //         `components` to `bbsSignature`, `bbsHeader`, `publicKey`, `hmacKey`, `mandatoryPointers`, and
  //         `signer_nym_entropy`, in that order, and add `featureOption` as a property.

  let decodedProofValue: Uint8Array
  try {
    decodedProofValue = multi.base64urlnopad.decode(proofValue)
  } catch {
    throw new ProcessingError(
      ProcessingErrorCode.PROOF_VERIFICATION_ERROR,
      "selective/serialize#parseBaseProofValue",
      "The proof value is not a valid base64url-no-pad string!",
    )
  }

  if (decodedProofValue.length < 3 || decodedProofValue[0] !== 0xd9 || decodedProofValue[1] !== 0x5d) {
    throw new ProcessingError(
      ProcessingErrorCode.PROOF_VERIFICATION_ERROR,
      "selective/serialize#parseBaseProofValue",
      "The proof value does not contain a valid CBOR prefix!",
    )
  }

  const featureMap: { [key: number]: Feature } = {
    0x02: Feature.BASELINE,
    0x04: Feature.ANONYMOUS_HOLDER_BINDING,
    0x06: Feature.PSEUDONYM,
    0x08: Feature.HOLDER_BINDING_PSEUDONYM,
  }

  const feature = featureMap[decodedProofValue[2]]
  if (!feature) {
    throw new ProcessingError(
      ProcessingErrorCode.PROOF_VERIFICATION_ERROR,
      "selective/serialize#parseBaseProofValue",
      "The proof value does not contain a valid CBOR prefix!",
    )
  }

  try {
    const components = cbor.decode(decodedProofValue.slice(3))
    const partialProofValue = assertBaseProofValue(components)
    if (feature === Feature.PSEUDONYM || feature === Feature.HOLDER_BINDING_PSEUDONYM) {
      if (!partialProofValue.signerNymEntropy) {
        throw new ProcessingError(
          ProcessingErrorCode.PROOF_VERIFICATION_ERROR,
          "selective/serialize#parseBaseProofValue",
          "The proof value SHOULD contain a valid signer nym entropy!",
        )
      }
    }
    return { ...partialProofValue, feature }
  } catch {
    throw new ProcessingError(
      ProcessingErrorCode.PROOF_VERIFICATION_ERROR,
      "selective/serialize#parseBaseProofValue",
      "The proof value is not a valid CBOR-encoded array.",
    )
  }
}

/**
 * Parse the components of a derived proof value.
 *
 * @param {string} proofValue A proof value encoded as a base64url-no-pad string.
 *
 * @returns {object} A single object of parsed derived proof, containing a set of six to nine components, having the
 * names `bbsProof`, `labelMap`, `mandatoryIndexes`, `selectiveIndexes`, `presentationHeader`, `featureOption`, and,
 * depending on the value of the `featureOption` parameter, possibly optional feature parameters `nym_domain`,
 * `pseudonym`, and `lengthBBSMessages`.
 *
 * @see https://www.w3.org/TR/vc-di-bbs/#parsederivedproofvalue
 */
export function parseDerivedProofValue(proofValue: string): DerivedProofValue {
  // Procedure:
  //
  // 1. If the `proofValue` string does not start with `u`, an error MUST be raised and SHOULD convey an error type of
  //    `PROOF_VERIFICATION_ERROR`.
  // 2. Initialize `decodedProofValue` to the result of base64url-no-pad-decoding the substring after the leading `u` in
  //    `proofValue`.
  // 3. Check that the BBS disclosure proof starts with an allowed header value and set the `featureOption` variable as
  //    follows:
  //
  //    3.1. If the `decodedProofValue` starts with the bytes `0xd9`, `0x5d`, and `0x03`, set `featureOption` to
  //         `baseline`.
  //    3.2. If the `decodedProofValue` starts with the bytes `0xd9`, `0x5d`, and `0x05`, set `featureOption` to
  //         `anonymous_holder_binding`.
  //    3.3. If the `decodedProofValue` starts with the bytes `0xd9`, `0x5d`, and `0x07`, set `featureOption` to
  //         `pseudonym`.
  //    3.4. If the `decodedProofValue` starts with the bytes `0xd9`, `0x5d`, and `0x09`, set `featureOption` to
  //         `holder_binding_pseudonym`.
  //    3.5. If the `decodedProofValue` starts with any other three bytes sequence, an error MUST be raised and SHOULD
  //         convey an error type of `PROOF_VERIFICATION_ERROR`.
  //
  // 4. Initialize `components` to an array that is the result of CBOR-decoding the bytes that follow the three-byte
  //    ECDSA-SD disclosure proof header. If the result is not an array of five, six, seven or eight elements, an error
  //    MUST be raised and SHOULD convey an error type of `PROOF_VERIFICATION_ERROR`.
  // 5. Replace the fourth element in `components` using the result of calling the `decompressLabelMap` function,
  //    passing the existing second element of `components` as `compressedLabelMap`.
  // 6. Return `derivedProofValue` as an object with properties set to the six, seven, or eight elements, using the
  //    names `bbsProof`, `labelMap`, `mandatoryIndexes`, `selectiveIndexes`, `presentationHeader`, and optional
  //    `nym_domain`, `pseudonym`, and/or `lengthBBSMessages`, respectively. In addition, add the `featureOption` and
  //    its value to the object.

  let decodedProofValue: Uint8Array
  try {
    decodedProofValue = multi.base64urlnopad.decode(proofValue)
  } catch {
    throw new ProcessingError(
      ProcessingErrorCode.PROOF_VERIFICATION_ERROR,
      "selective/serialize#parseDerivedProofValue",
      "The proof value is not a valid base64url-no-pad string!",
    )
  }

  if (decodedProofValue.length < 3 || decodedProofValue[0] !== 0xd9 || decodedProofValue[1] !== 0x5d) {
    throw new ProcessingError(
      ProcessingErrorCode.PROOF_VERIFICATION_ERROR,
      "selective/serialize#parseDerivedProofValue",
      "The proof value does not contain a valid CBOR prefix!",
    )
  }

  const featureMap: { [key: number]: Feature } = {
    0x03: Feature.BASELINE,
    0x05: Feature.ANONYMOUS_HOLDER_BINDING,
    0x07: Feature.PSEUDONYM,
    0x09: Feature.HOLDER_BINDING_PSEUDONYM,
  }

  const feature = featureMap[decodedProofValue[2]]
  if (!feature) {
    throw new ProcessingError(
      ProcessingErrorCode.PROOF_VERIFICATION_ERROR,
      "selective/serialize#parseDerivedProofValue",
      "The proof value does not contain a valid CBOR prefix!",
    )
  }

  try {
    const components = cbor.decode(decodedProofValue.slice(3))
    const partialProofValue = assertCompressedProofValue(components)
    if (feature === Feature.ANONYMOUS_HOLDER_BINDING && !partialProofValue.lengthBBSMessages) {
      throw new ProcessingError(
        ProcessingErrorCode.PROOF_VERIFICATION_ERROR,
        "selective/serialize#parseDerivedProofValue",
        "The proof value SHOULD contain a valid BBS message length!",
      )
    }
    if (feature === Feature.PSEUDONYM || feature === Feature.HOLDER_BINDING_PSEUDONYM) {
      if (!partialProofValue.nymDomain || !partialProofValue.pseudonym || !partialProofValue.lengthBBSMessages) {
        throw new ProcessingError(
          ProcessingErrorCode.PROOF_VERIFICATION_ERROR,
          "selective/serialize#parseDerivedProofValue",
          "The proof value SHOULD contain a valid nym domain, pseudonym, and BBS message length!",
        )
      }
    }
    const labelMap = decompressLabelMap(partialProofValue.compressedLabelMap)
    return { ...partialProofValue, feature, labelMap }
  } catch {
    throw new ProcessingError(
      ProcessingErrorCode.PROOF_VERIFICATION_ERROR,
      "selective/serialize#parseDerivedProofValue",
      "The proof value is not a valid CBOR-encoded array.",
    )
  }
}
