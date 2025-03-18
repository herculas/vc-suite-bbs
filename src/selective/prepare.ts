import { basic, Cipher } from "@herculas/bbs-signature"
import {
  type Canonize,
  type Compact,
  type Expand,
  format,
  type Hasher,
  type HMAC,
  type JsonLdObject,
  type LabelMap,
  ProcessingError,
  ProcessingErrorCode,
  type Proof,
  rdfc,
  selective,
  type ToRdf,
  type URNScheme,
} from "@herculas/vc-data-integrity"

import { Feature } from "../constant/feature.ts"
import { parseBaseProofValue, parseDerivedProofValue } from "./serialize.ts"

import type { DisclosureData, VerifyData } from "./types.ts"

/**
 * Create data to be used to generate a derived proof.
 *
 * @param {JsonLdDocument} document A JSON-LD document.
 * @param {Proof} proof An BBS base proof.
 * @param {Array<string>} selectivePointers An array of JSON pointers to used to selectively disclose statements.
 * @param {object} [options] Any custom JSON-LD API options, such as a document loader.
 *
 * @returns {Promise<DisclosureData>} A single object containing the following fields: `bbsProof`, `labelMap`,
 * `mandatoryIndexes`, `selectiveIndexes`, `presentationHeader`, `revealDocument`, and if computed, `pseudonym`.
 *
 * @see https://www.w3.org/TR/vc-di-bbs/#createdisclosuredata
 */
export async function createDisclosureData(
  document: JsonLdObject,
  proof: Proof,
  selectivePointers: Array<string>,
  options?:
    & {
      feature?: Feature
      cipher?: Cipher
      presentationHeader?: Uint8Array
      urnScheme?: URNScheme
      randomString?: string
    }
    & Expand
    & Compact
    & ToRdf
    & Partial<Canonize>,
): Promise<DisclosureData> {
  // Procedure:
  //
  // 1. Initialize `bbsSignature`, `bbsHeader`, `publicKey`, `hmacKey`, and `mandatoryPointers` to the values of the
  //    associated properties in the object returned of calling the `parseBaseProofValue` function, passing the
  //    `proofValue` from `proof`.
  // 2. Initialize `hmac` to an HMAC API using `hmacKey`. The HMAC uses the same hash algorithm used in the signature
  //    algorithm, i.e., SHA-256.
  // 3. Initialize `labelMapFactoryFunction` to the result of calling the `createShuffledIdLabelMapFunction` function,
  //    passing `hmac`.
  // 4. Initialize `combinedPointers` to the concatenation of `mandatoryPointers` and `selectivePointers`.
  // 5. Initialize `groupDefinitions` to a map with the following entries: key of the string `mandatory` and value of
  //    `mandatoryPointers`, key of the string `selective` and value of `selectivePointers`, and key of the string
  //    `combined` and value of `combinedPointers`.
  // 6. Initialize `groups` and `labelMap` to their associated values in the result of calling the
  //    `canonicalizeAndGroup` function, passing `document`, `labelMapFactoryFunction`, `groupDefinitions`, and any
  //    custom JSON-LD API options as parameters. Note: This step transforms the document into an array of canonical
  //    N-Quad strings whose order has been shuffled based on `hmac`-applied blank node identifiers, and groups the
  //    N-Quad strings according to selections based on JSON pointers.
  // 7. Compute the mandatory indexes relative to their positions in the combined statement list, i.e., find the
  //    position at which a mandatory statement occurs in the list of combined statements. One method for doing this is
  //    given below.
  //
  //    7.1. Initialize `mandatoryIndexes` to an empty array. Set `mandatoryMatch` to `groups.mandatory.matching` map;
  //         set `combinedMatch` to `groups.combined.matching`; and set `combinedIndexes` to the ordered array of just
  //         the keys of the `combinedMatch` map.
  //    7.2. For each `key` in `mandatoryMatch` map, find its index in the `combinedIndexes` array (e.g.,
  //         `combinedIndexes.indexOf(key)`), and add this value to the `mandatoryIndexes` array.
  //
  // 8. Compute the selective indexes relative their positions in the non-mandatory statement list, i.e., find the
  //    position at which a selective statement occurs in the list of non-mandatory statements. One method for doing
  //    this is given below.
  //
  //    8.1. Initialize `selectiveIndexes` to an empty array. Set `selectiveMatch` to `groups.selective.matching` map;
  //         set `mandatoryNonMatch` to the map `groups.mandatory.nonMatching`; and set `nonMandatoryIndexes` to the
  //         ordered array of just the keys of the `mandatoryNonMatch` map.
  //    8.2. For each `key` in `selectiveMatch` map, find its index in the `nonMandatoryIndexes` array (e.g.,
  //         `nonMandatoryIndexes.indexOf(key)`), and add this value to the `selectiveIndexes` array.
  //
  // 9. Initialize `bbsMessages` to an array of byte arrays containing the values in the `nonMandatory` array of strings
  //    encoded using the UTF-8 character encoding.
  // 10. Set `bbsProof` to the value computed by the appropriate procedure given below based on the value of the
  //     `featureOption` parameter.
  //
  //     10.1. If `featureOption` equals `baseline`, set `bbsProof` to the value computed by the `ProofGen` procedure
  //           from [CFRG-BBS-SIGNATURE], i.e., `ProofGen(PK, signature, header, ph, messages, disclosed_indexes)`,
  //           where `PK` is the original issuers public key, signature is the `bbsSignature`, `header` is the
  //           `bbsHeader`, `ph` is the `presentationHeader`, `messages` is `bbsMessages`, and `disclosed_indexes` is
  //           the `selectiveIndexes` array.
  //     10.2. If `featureOption` equals `anonymous_holder_binding`, set `bbsProof` to the value computed by the
  //           `BlindProofGen` procedure from [CFRG-BLIND-BBS-SIGNATURE], where `PK` is the original issuers public key,
  //           `signature` is the `bbsSignature`, `header` is the `bbsHeader`, `ph` is the `presentationHeader`,
  //           `messages` is `bbsMessages`, `disclosed_indexes` is the `selectiveIndexes` array, and
  //           `commitment_with_proof`. The holder will also furnish its `holder_secret`, and the `proverBlind` that was
  //           used to compute the `commitment_with_proof`.
  //     10.3. If `featureOption` equals `pseudonym`, use the "Verification and Finalization" operation from [CFRG-
  //           PSEUDONYM-BBS-SIGNATURE] with an empty `committed_messages` array to both verify the `bbsSignature` and
  //           compute the `nym_secret` value. This operation uses the `prover_nym`, `signer_nym_entropy`, and
  //           `secret_prover_blind` values.
  //           Determine the `nym_domain`. This might be specified by the verifier or set by the holder, depending on
  //           the usage scenario. Use the "Proof Generation with Pseudonym" operation from [CFRG-PSEUDONYM-BBS-
  //           SIGNATURE] to produce the derived proof. This operation takes as inputs the original issuer's public key
  //           as `PK`, the `bbsSignature` as `signature`, the `bbsHeader` as `header`, the `presentationHeader` as
  //           `ph`, the `bbsMessages` as `messages`, the `selectiveIndexes` as `disclosed_indexes`, a `nym_secret`, a
  //           `nym_domain`, an empty array for `committed_messages`, and a `secret_prover_blind`. In addition to
  //           providing the raw cryptographic proof value which is assigned to `bbsProof`, it also returns the
  //           `pseudonym`.
  //     10.4. If `featureOption` equals `holder_binding_pseudonym`, use the "Verification and Finalization" operation
  //           from [CFRG-PSEUDONYM-BBS-SIGNATURE] with the `committed_messages` array containing the `holder_secret` as
  //           its only value, to both verify the `bbsSignature` and compute the `nym_secret` value. This operation uses
  //           the `prover_nym`, `signer_nym_entropy`, and `secret_prover_blind`.
  //           Determine the `nym_domain`. This might be specified by the verifier or set by the holder depending on the
  //           usage scenario. Use the "Proof Generation with Pseudonym" operation from [CFRG-PSEUDONYM-BBS-SIGNATURE]
  //           to produce the derived proof. This operation takes as inputs the original issuers public key as `PK`, the
  //           `bbsSignature` as `signature`, the `bbsHeader` as `header`, the `presentationHeader` as `ph`, the
  //           `bbsMessages` as `messages`, the `selectiveIndexes` as `disclosed_indexes`, a `nym_secret`, a
  //           `nym_domain`, the only value of the `committed_messages` array as `holder_secret`, and a
  //           `secret_prover_blind`. In addition to providing the raw cryptographic proof value which is assigned to
  //           `bbsProof`, it also returns the `pseudonym`.
  //
  // 11. If `featureOption` equals `anonymous_holder_binding`, `pseudonym`, or `holder_binding_pseudonym`, set the
  //     `lengthBBSMessages` parameter to the length of the `bbsMessages` array.
  // 12. Initialize `revealDocument` to the result of the `selectJsonLd` algorithm, passing `document`, and
  //     `combinedPointers` as pointers.
  // 13. Run the RDF Dataset Canonicalization Algorithm on the joined `combinedGroup.deskolemizedNQuads`, passing any
  //     custom options, and get the canonical bnode identifier map, `canonicalIdMap`. Note: This map includes the
  //     canonical blank node identifiers that a verifier will produce when they canonicalize the reveal document.
  // 14. Initialize `verifierLabelMap` to an empty map. This map will map the canonical blank node identifiers produced
  //     by the verifier when they canonicalize the revealed document, to the blank node identifiers that were
  //     originally signed in the base proof.
  // 15. For each key `inputLabel` and value `verifierLabel` in `canonicalIdMap`:
  //
  //     15.1. Add an entry to `verifierLabelMap`, using `verifierLabel` as the `key`, and the value associated with
  //           `inputLabel` as a key in `labelMap` as the value.
  //
  // 16. Return an object with properties matching `bbsProof`, `verifierLabelMap` for `labelMap`, `mandatoryIndexes`,
  //     `selectiveIndexes`, `revealDocument`, `pseudonym`, and, if computed, `lengthBBSMessages`.

  const cipher = options?.cipher ?? Cipher.XMD_SHA_256
  const feature = options?.feature ?? Feature.BASELINE

  const { bbsSignature, bbsHeader, publicKey, hmacKey, mandatoryPointers } = parseBaseProofValue(proof.proofValue!)
  const hmacCryptoKey = await crypto.subtle.importKey(
    "raw",
    hmacKey,
    { name: "HMAC", hash: "SHA-256" },
    true,
    ["sign", "verify"],
  )
  const hmac: HMAC = async (data: Uint8Array) =>
    new Uint8Array(await crypto.subtle.sign(hmacCryptoKey.algorithm, hmacCryptoKey, data))
  const labelMapFactoryFunction = selective.createShuffledIdLabelMapFunction(hmac)

  const combinedPointers = [...mandatoryPointers, ...selectivePointers]
  const groupDefinitions: Map<string, Array<string>> = new Map([
    ["mandatory", mandatoryPointers],
    ["selective", selectivePointers],
    ["combined", combinedPointers],
  ])
  const { groups, labelMap } = await selective.canonicalizeAndGroup(
    document,
    labelMapFactoryFunction,
    groupDefinitions,
    options,
  )

  const mandatoryMatch = groups.get("mandatory")!.matching
  const combinedMatch = groups.get("combined")!.matching
  const selectiveMatch = groups.get("selective")!.matching
  const mandatoryNonMatch = groups.get("mandatory")!.nonMatching

  const mandatoryIndexes = Array.from(combinedMatch.keys()).filter((index) => mandatoryMatch.has(index))
  const selectiveIndexes = Array.from(mandatoryNonMatch.keys()).filter((index) => selectiveMatch.has(index))
  const bbsMessages = [...mandatoryNonMatch.values()].map((nq) => format.bytesToHex(new TextEncoder().encode(nq)))

  let bbsProof: string
  if (feature === Feature.BASELINE) {
    bbsProof = basic.prove(
      format.bytesToHex(publicKey),
      format.bytesToHex(bbsSignature),
      format.bytesToHex(bbsHeader),
      options?.presentationHeader ? format.bytesToHex(options.presentationHeader) : undefined,
      bbsMessages,
      selectiveIndexes,
      cipher,
    )
  } else {
    throw new ProcessingError(
      ProcessingErrorCode.PROOF_GENERATION_ERROR,
      "selective/prepare#createDisclosureData",
      `Unsupported feature option: ${feature}`,
    )
  }

  const revealDocument = selective.selectJsonLd(combinedPointers, document)

  let canonicalIdMap: LabelMap = new Map()
  const nQuads = groups.get("combined")!.deskolemizedNQuads.join("")
  await rdfc.canonize(nQuads, {
    ...options,
    algorithm: "RDFC-1.0",
    inputFormat: "application/n-quads",
    format: "application/n-quads",
    canonicalIdMap,
  })
  canonicalIdMap = new Map(
    Array.from(canonicalIdMap, ([key, value]) => [key.replace(/^_:/, ""), value.replace(/^_:/, "")]),
  )

  const verifierLabelMap: LabelMap = new Map()
  for (const [inputLabel, verifierLabel] of canonicalIdMap) {
    verifierLabelMap.set(verifierLabel, labelMap.get(inputLabel)!)
  }

  return {
    bbsProof: format.hexToBytes(bbsProof),
    labelMap: verifierLabelMap,
    mandatoryIndexes,
    selectiveIndexes,
    presentationHeader: options?.presentationHeader ?? new Uint8Array(),
    revealDocument,
  }
}

/**
 * Create the data needed to perform verification of an BBS-protected verifiable credential.
 *
 * @param {JsonLdObject} document A JSON-LD document.
 * @param {Proof} proof An BBS disclosure proof.
 * @param {object} [options] Any custom JSON-LD API options, such as a document loader.
 *
 * @returns {Promise<VerifyData>} A single verify data object containing the following fields: `bbsProof`, `proofHash`,
 * `mandatoryHash`, `selectiveIndexes`, `presentationHeader`, `nonMandatory`, `featureOption`, and, possibly,
 * `pseudonym` and/or `lengthBBSMessages`.
 *
 * @see https://www.w3.org/TR/vc-di-bbs/#createverifydata
 */
export async function createVerifyData(
  document: JsonLdObject,
  proof: Proof,
  options?:
    & ToRdf
    & Partial<Canonize>,
): Promise<VerifyData> {
  // Procedure:
  //
  // 1. Initialize `proofHash` to the result of perform RDF Dataset Canonicalization on the `proof` options, i.e., the
  //    proof portion of the document with the `proofValue` removed. The hash used is the same as the one used in the
  //    signature algorithm, i.e., SHA-256. Note: This step can be performed in parallel; it only needs to be completed
  //    before this algorithm needs to use the `proofHash` value.
  // 2. Initialize `bbsProof`, `labelMap`, `mandatoryIndexes`, `selectiveIndexes`, `presentationHeader`,
  //    `featureOption`, and, possibly, `pseudonym` and/or `lengthBBSMessages` to the values associated with their
  //    property names in the object returned when calling the `parseDerivedProofValue` function, passing `proofValue`
  //    from `proof`.
  // 3. Initialize `labelMapFactoryFunction` to the result of calling the `createLabelMapFunction` function, passing
  //    `labelMap`.
  // 4. Initialize `nQuads` to the result of calling the `labelReplacementCanonicalizeJsonLd` function, passing
  //    `document`, `labelMapFactoryFunction`, and any custom JSON-LD API options. Note: This step transforms the
  //    document into an array of canonical N-Quads with pseudorandom blank node identifiers based on `labelMap`.
  // 5. Initialize `mandatory` to an empty array.
  // 6. Initialize `nonMandatory` to an empty array.
  // 7. For each entry (`index`, `nq`) in `nQuads`, separate the N-Quads into mandatory and non-mandatory categories:
  //
  //    7.1. If `mandatoryIndexes` includes `index`, add `nq` to `mandatory`.
  //    7.2. Otherwise, add `nq` to `nonMandatory`.
  //
  // 8. Initialize `mandatoryHash` to the result of calling the `hashMandatory` function, passing `mandatory`.
  // 9. Return an object with properties matching `baseSignature`, `proofHash`, `nonMandatory`, `mandatoryHash`,
  //    `selectiveIndexes`, `featureOption`, and, possibly, `pseudonym` and/or `lengthBBSMessages`.

  const hasher: Hasher = async (data: Uint8Array) => new Uint8Array(await crypto.subtle.digest("SHA-256", data))
  const proofHashPromise = _hashCanonizedProof(document, proof, hasher, options)

  const {
    bbsProof,
    labelMap,
    mandatoryIndexes,
    selectiveIndexes,
    presentationHeader,
    feature,
    pseudonym,
    lengthBBSMessages,
  } = parseDerivedProofValue(proof.proofValue!)
  const labelMapFactoryFunction = selective.createLabelMapFunction(labelMap)
  const nQuads = await selective.labelReplacementCanonicalizeJsonLd(document, labelMapFactoryFunction, options)

  const mandatory: Array<string> = []
  const nonMandatory: Array<string> = []

  nQuads.canonicalNQuads.forEach((nq, index) => {
    if (mandatoryIndexes.includes(index)) {
      mandatory.push(nq)
    } else {
      nonMandatory.push(nq)
    }
  })

  const mandatoryHash = await selective.hashMandatoryNQuads(mandatory, hasher)
  return {
    bbsProof,
    proofHash: await proofHashPromise,
    mandatoryHash,
    selectiveIndexes,
    presentationHeader,
    nonMandatory,
    feature,
    pseudonym,
    lengthBBSMessages,
  }
}

async function _hashCanonizedProof(
  document: JsonLdObject,
  proof: Proof,
  hasher: Hasher,
  options?: ToRdf & Partial<Canonize>,
) {
  options = {
    algorithm: "RDFC-1.0",
    safe: true,
    rdfDirection: "i18n-datatype",
    ...options,
    produceGeneralizedRdf: false,
  }
  proof = {
    "@context": document["@context"],
    ...proof,
  }
  delete proof.proofValue
  const rdf = await rdfc.toRdf(proof, options)
  const canonized = await rdfc.canonize(rdf, options as Canonize)
  return await hasher(new TextEncoder().encode(canonized))
}
