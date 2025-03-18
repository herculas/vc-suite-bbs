import { basic, blind, type Cipher, nym } from "@herculas/bbs-signature"
import {
  type Canonize,
  type Compact,
  type Credential,
  document,
  type Expand,
  format,
  type Hasher,
  type HMAC,
  type LoadDocumentCallback,
  ProcessingError,
  ProcessingErrorCode,
  type Proof,
  rdfc,
  selective,
  type ToRdf,
  type URNScheme,
} from "@herculas/vc-data-integrity"

import { Feature } from "../constant/feature.ts"

import { Bls12381G2Keypair } from "../key/keypair.ts"
import { serializeBaseProofValue, serializeDerivedProofValue } from "../selective/serialize.ts"

import * as SUITE_CONSTANT from "../constant/suite.ts"
import { createDisclosureData } from "../selective/prepare.ts"

/**
 * Transform an unsecured input document into a transformed document that is ready to be provided as input to the
 * hashing algorithm.
 *
 * @param {Credential} unsecuredDocument An unsecured input document to be transformed.
 * @param {object} options A set of options to use when transforming the document. The transformation options MUST
 * contain a type identifier `type` for the cryptographic suite, a cryptosuite identifier `cryptosuite`, and a
 * verification method `verificationMethod`. The transformation options MUST contain an array of mandatory JSON pointers
 * `mandatoryPointers` and MAY contain additional options, such as a JSON-LD document loader.
 *
 * @returns {Promise<TransformedDocument>} Resolve to a transformed data document, which is a map containing the
 * mandatory pointers, mandatory revealed values, non-mandatory revealed values, and the HMAC key.
 *
 * @see https://www.w3.org/TR/vc-di-bbs/#base-proof-transformation-bbs-2023
 */
export async function transform(
  unsecuredDocument: Credential,
  options:
    & {
      feature: Feature
      proof: Proof
      mandatoryPointers: Array<string>
      documentLoader?: LoadDocumentCallback
      urnScheme?: URNScheme
      randomString?: string
    }
    & Expand
    & Compact
    & ToRdf
    & Partial<Canonize>,
): Promise<TransformedDocument> {
  // Procedure:
  //
  // 1. Initialize `hmac` to an HMAC API using a locally generated and exportable HMAC key. The HMAC uses the same hash
  //    algorithm used in the signature algorithm, i.e., SHA-256. Per the recommendations of [RFC-2104], the HMAC key
  //    MUST be the same length as the digest size; for SHA-256, this is 256 bits or 32 bytes.
  // 2. Initialize `labelMapFactoryFunction` to the result of calling the `createShuffledIdLabelMapFunction` algorithm
  //    passing `hmac` as HMAC.
  // 3. Initialize `groupDefinitions` to a map with an entry with a key of the string "mandatory" and a value of
  //    `mandatoryPointers`.
  // 4. Initialize `groups` to the result of calling the `canonicalizeAndGroup` function, passing
  //    `labelMapFactoryFunction`, `groupDefinitions`, `unsecuredDocument` as `document`, and any custom JSON-LD API
  //    options. Note: This step transforms the `document` into an array of canonical N-Quads whose order has been
  //    shuffled based on `hmac` applied blank node identifiers, and groups the N-Quad strings according to selections
  //    based on JSON pointers.
  // 5. Initialize `mandatory` to the values in the `groups.mandatory.matching` map.
  // 6. Initialize `nonMandatory` to the values in the `groups.mandatory.nonMatching` map.
  // 7. Initialize `hmacKey` to the result of exporting the HMAC key from `hmac`.
  // 8. Return an object with "mandatoryPointers" set to `mandatoryPointers`, "mandatory" set to `mandatory`,
  //    "nonMandatory" set to `nonMandatory`, and "hmacKey" set to `hmacKey`.

  if (
    options.proof.type !== SUITE_CONSTANT.GENERAL_PROOF_TYPE ||
    options.proof.cryptosuite !== SUITE_CONSTANT.SUITE_BBS
  ) {
    throw new ProcessingError(
      ProcessingErrorCode.PROOF_TRANSFORMATION_ERROR,
      "suite/core#transform",
      "The proof type or cryptosuite is not supported.",
    )
  }

  const rawHmacKey = crypto.getRandomValues(new Uint8Array(32))
  const hmacKey = await crypto.subtle.importKey(
    "raw",
    rawHmacKey,
    { name: "HMAC", hash: "SHA-256" },
    true,
    ["sign", "verify"],
  )
  const hmac: HMAC = async (data: Uint8Array) =>
    new Uint8Array(await crypto.subtle.sign(hmacKey.algorithm, hmacKey, data))
  const labelMapFactoryFunction = selective.createShuffledIdLabelMapFunction(hmac)

  const groupDefinitions: Map<string, Array<string>> = new Map([
    ["mandatory", options.mandatoryPointers],
  ])
  const { groups } = await selective.canonicalizeAndGroup(
    unsecuredDocument,
    labelMapFactoryFunction,
    groupDefinitions,
    options,
  )

  const mandatory = groups.get("mandatory")?.matching!
  const nonMandatory = groups.get("mandatory")?.nonMatching!

  return {
    mandatoryPointers: options.mandatoryPointers,
    mandatory,
    nonMandatory,
    hmacKey: rawHmacKey,
  }
}

/**
 * Generate a proof configuration from a set of proof options that is used as input to the proof hashing algorithm.
 *
 * @param {Credential} unsecuredDocument An unsecured input document to generate a proof configuration from.
 * @param {object} options A set of proof options to generate a proof configuration from. The proof options MUST contain
 * a type identifier `type` for the cryptographic suite and a cryptosuite identifier `cryptosuite`.
 *
 * @returns {Promise<string>} Resolve to a proof configuration.
 *
 * @see https://www.w3.org/TR/vc-di-bbs/#base-proof-configuration-bbs-2023
 */
export async function config(
  unsecuredDocument: Credential,
  options: {
    proof: Proof
    documentLoader: LoadDocumentCallback
  },
): Promise<string> {
  // Procedure:
  //
  // 1. Let `proofConfig` be a clone of the `options` object.
  // 2. If `proofConfig.type` is not set to `DataIntegrityProof` and/or `proofConfig.cryptosuite` is not set to
  //    `bbs-2023`, an error MUST be raised and SHOULD convey an error type of `PROOF_GENERATION_ERROR`.
  // 3. If `proofConfig.created` is set and if the value is not a valid datetime, an error MUST be raised and SHOULD
  //    convey an error type of `PROOF_GENERATION_ERROR`.
  // 4. Set `proofConfig.@context` to `unsecuredDocument.@context`.
  // 5. Let `canonicalProofConfig` be the result of applying the RDF Dataset Canonicalization Algorithm to the
  //    `proofConfig`.
  // 6. Return `canonicalProofConfig`.

  const proofConfig = structuredClone(options.proof)

  if (
    proofConfig.type !== SUITE_CONSTANT.GENERAL_PROOF_TYPE ||
    proofConfig.cryptosuite !== SUITE_CONSTANT.SUITE_BBS
  ) {
    throw new ProcessingError(
      ProcessingErrorCode.PROOF_GENERATION_ERROR,
      "suite/core#configSd",
      "The proof type or cryptosuite is not supported.",
    )
  }

  if (proofConfig.created && !Date.parse(proofConfig.created)) {
    throw new ProcessingError(
      ProcessingErrorCode.PROOF_GENERATION_ERROR,
      "suite/core#configSd",
      "The proof creation date is not a valid datetime.",
    )
  }

  proofConfig["@context"] = unsecuredDocument["@context"]

  const canonicalProofConfig = await rdfc.normalize(proofConfig, {
    algorithm: "URDNA2015",
    format: "application/n-quads",
    documentLoader: options.documentLoader,
  })

  return canonicalProofConfig
}

/**
 * Cryptographically hash a transformed data document and proof configuration into cryptographic hash data that is
 * ready to be provided as input to the proof serialization algorithm.
 *
 * @param {TransformedDocument} transformedDocument A transformed data document to be hashed.
 * @param {string} canonicalProofConfig A canonical proof configuration.
 *
 * @returns {Promise<HashData>} Resolve to a cryptographic hash data.
 *
 * @see https://www.w3.org/TR/vc-di-bbs/#base-proof-hashing-bbs-2023
 */
export async function hash(
  transformedDocument: TransformedDocument,
  canonicalProofConfig: string,
): Promise<HashData> {
  // Procedure:
  //
  // 1. Initialize `proofHash` to the result of calling the RDF Dataset Canonicalization algorithm on
  //    `canonicalProofConfig` and then cryptographically hashing the result using the same hash that is used by the
  //    signature algorithm, i.e., SHA-256. Note: This step can be performed in parallel; it only needs to be completed
  //    before this algorithm terminates as the result is part of the return value.
  // 2. Initialize `mandatoryHash` to the result of calling the `hashMandatoryNQuads` function, passing
  //    `transformedDocument.mandatory` and using the SHA-256 hash algorithm.
  // 3. Initialize `hashData` as a deep copy of `transformedDocument` and add `proofHash` as `proofHash` and
  //    `mandatoryHash` as `mandatoryHash` to that object.
  // 4. Return `hashData` as hash data.

  const hasher: Hasher = async (data: Uint8Array) => new Uint8Array(await crypto.subtle.digest("SHA-256", data))
  const proofHash = await hasher(new TextEncoder().encode(canonicalProofConfig))
  const mandatory = [...transformedDocument.mandatory.values()]
  const mandatoryHash = await selective.hashMandatoryNQuads(mandatory, hasher)
  const clonedDocument = structuredClone(transformedDocument)
  return {
    ...clonedDocument,
    proofHash,
    mandatoryHash,
  }
}

/**
 * Create a base proof. This function will be called by an issuer of an BBS-protected verifiable credential. The base
 * proof is to be given only to the holder, who is responsible for generating a derived proof from it, exposing only
 * selectively disclosed details in the proof to a verifier.
 *
 * @param {HashData} hashData A cryptographic hash data to serialize.
 * @param {object} options A set of options to use when serializing the hash data. The proof options MUST contain a type
 * identifier `type` for the cryptographic suite, and MAY contain a cryptosuite identifier `cryptosuite`. If `feature`
 * is set to "anonymous_holder_binding", "pseudonym", or "holder_binding_pseudonym", the `commitment_with_proof` input
 * MUST be supplied; if not supplied, an error MUST be raised and SHOULD convey an error type of
 * `PROOF_GENERATION_ERROR`. If `feature` is set to "pseudonym" or "holder_binding_pseudonym", the `signer_nym_entropy`
 * input MUST be supplied; if not supplied, an error MUST be raised and SHOULD convey an error type of
 * `PROOF_GENERATION_ERROR`.
 *
 * @returns {Promise<string>} Resolve to a serialized digital proof.
 *
 * @see https://www.w3.org/TR/vc-di-bbs/#base-proof-serialization-bbs-2023
 */
export async function serialize(
  hashData: HashData,
  options: {
    feature: Feature
    proof: Proof
    documentLoader: LoadDocumentCallback
    cipher?: Cipher
    commitmentWithProof?: string
    signerNymEntropy?: string
  },
): Promise<string> {
  // Procedure:
  //
  // 1. Initialize `proofHash`, `mandatoryPointers`, `mandatoryHash`, `nonMandatory`, and `hmacKey` to the values
  //    associated with their property names in `hashData`.
  // 2. Initialize `bbsHeader` to the concatenation of `proofHash` and `mandatoryHash` in that order.
  // 3. Initialize `bbsMessages` to an array of byte arrays containing the values in the `nonMandatory` array of strings
  //    encoded using the UTF-8 character encoding.
  // 4. Compute the `bbsSignature` using the procedures below, dependent on the value of `featureOption`.
  //
  //    4.1. If `featureOption` equals "baseline", compute the `bbsSignature` using the `Sign` procedure of [CFRG-BBS-
  //         SIGNATURE], with appropriate key material, `bbsHeader` for the `header`, and `bbsMessages` for the
  //         `messages`.
  //    4.2. If `featureOption` equals "anonymous_holder_binding", compute the `bbsSignature` using the `BlindSign`
  //         procedure of [CFRG-BLIND-BBS-SIGNATURE], with appropriate key material, `commitment_with_proof` for the
  //         `commitment_with_proof`, `bbsHeader` for the `header`, and `bbsMessages` for the `messages`.
  //    4.3. If `featureOption` equals "pseudonym" or "holder_binding_pseudonym", the issuer generates a
  //         cryptographically random value for the `signer_nym_entropy` and computes the `bbsSignature` using the
  //         "Blind Issuance" operation from [CFRG-PSEUDONYM-BBS-SIGNATURE], with appropriate key material, `bbsHeader`
  //         for the `header`, `bbsMessages` for the `messages`, `commitment_with_proof` for the
  //         `commitment_with_proof`, and `signer_nym_entropy` for the `signer_nym_entropy`. If the issuer might ever
  //         need to reissue a credential to this holder that is bound to the same `nym_secret`, they should retain the
  //         `signer_nym_entropy` value; otherwise, this value can be discarded.
  // 5. Initialize `proofValue` to the result of calling the `serializeBaseProofValue` function, passing `bbsSignature`,
  //    `bbsHeader`, `publicKey`, `hmacKey`, `mandatoryPointers`, `featureOption`, and, depending on the `featureOption`
  //    value, `signer_nym_entropy`, as parameters.
  // 8. Return `proofValue` as digital proof.

  const { proofHash, mandatoryHash, mandatoryPointers, nonMandatory, hmacKey } = hashData

  const bbsHeader = format.bytesToHex(format.concatenate(proofHash, mandatoryHash))
  const bbsMessages = [...nonMandatory.values()].map((message) => format.bytesToHex(new TextEncoder().encode(message)))

  const method = await document.retrieveVerificationMethod(
    options.proof.verificationMethod!,
    new Set(),
    { documentLoader: options.documentLoader },
  )
  const keypair = await Bls12381G2Keypair.import(method)
  if (!keypair.privateKey || !keypair.publicKey) {
    throw new ProcessingError(
      ProcessingErrorCode.INVALID_VERIFICATION_METHOD,
      "suite/core#serialize",
      "The keypair does not contain a private or public key.",
    )
  }

  const secretKey = format.bytesToHex(keypair.privateKey)
  const publicKey = format.bytesToHex(keypair.publicKey)

  let bbsSignature: string
  if (options.feature === Feature.BASELINE) {
    bbsSignature = basic.sign(secretKey, publicKey, bbsHeader, bbsMessages, options.cipher)
  } else if (options.feature === Feature.ANONYMOUS_HOLDER_BINDING) {
    if (!options.commitmentWithProof) {
      throw new ProcessingError(
        ProcessingErrorCode.PROOF_GENERATION_ERROR,
        "suite/core#serialize",
        `The commitment with proof MUST be supplied in feature ${options.feature}.`,
      )
    }
    bbsSignature = blind.sign(
      secretKey,
      publicKey,
      options.commitmentWithProof,
      bbsHeader,
      bbsMessages,
      options.cipher,
    )
  } else if (options.feature === Feature.PSEUDONYM || options.feature === Feature.HOLDER_BINDING_PSEUDONYM) {
    if (!options.commitmentWithProof || !options.signerNymEntropy) {
      throw new ProcessingError(
        ProcessingErrorCode.PROOF_GENERATION_ERROR,
        "suite/core#serialize",
        `The commitment with proof and signer nym entropy MUST be supplied in feature ${options.feature}.`,
      )
    }
    bbsSignature = nym.sign(
      secretKey,
      publicKey,
      options.signerNymEntropy,
      options.commitmentWithProof,
      bbsHeader,
      bbsMessages,
      options.cipher,
    )
  } else {
    throw new ProcessingError(
      ProcessingErrorCode.PROOF_GENERATION_ERROR,
      "suite/core#serialize",
      `Unsupported BBS signature feature ${options.feature}!`,
    )
  }

  return serializeBaseProofValue({
    bbsSignature: format.hexToBytes(bbsSignature),
    bbsHeader: format.hexToBytes(bbsHeader),
    publicKey: format.hexToBytes(publicKey),
    hmacKey,
    mandatoryPointers,
    feature: options.feature,
    signerNymEntropy: options.signerNymEntropy ? format.hexToBytes(options.signerNymEntropy) : undefined,
  })
}

/**
 * Create a selective disclosure derived proof. This function will be called by a holder of an BBS-protected verifiable
 * credential. The derived proof is to be given to a verifier, who can use it to verify the proof and the disclosed
 * details.
 *
 * @param {Credential} document A verifiable credential to derive a selective disclosure proof from.
 * @param {Proof} proof A BBS base proof to derive a selective disclosure proof from.
 * @param {object} options A set of options to use when deriving the selective disclosure proof. The options contain an
 * array of JSON pointers `selectivePointers` to use to selectively disclose statements, an optional BBS presentation
 * header `presentationHeader`.
 *
 * @returns {Promise<string>} Resolve to a derived proof value.
 *
 * @see https://www.w3.org/TR/vc-di-bbs/#add-derived-proof-bbs-2023
 */
export async function derive(
  document: Credential,
  proof: Proof,
  options: {
    feature: Feature
    selectivePointers: Array<string>
    documentLoader: LoadDocumentCallback
    presentationHeader?: string
    urnScheme?: URNScheme
    randomString?: string
    nymDomain?: string
    lengthBBSMessages?: number
  },
): Promise<string> {
  // Procedure:
  //
  // 1. Initialize `bbsProof`, `labelMap`, `mandatoryIndexes`, `selectiveIndexes`, and `revealDocument` to the values
  //    associated with their property names in the object returned when calling the `createDisclosureData` function,
  //    passing the `document`, `proof`, `selectivePointers`, `presentationHeader`, `featureOption`, required additional
  //    inputs based on the `featureOption`, and any custom JSON-LD API options, such as a document loader.
  // 3. Replace `proofValue` in `newProof` with the result of calling the `serializeDerivedProofValue` function, passing
  //    `bbsProof`, `labelMap`, `mandatoryIndexes`, `selectiveIndexes`, `featureOption`, and any required inputs
  //    indicated by the `featureOption`.

  const {
    bbsProof,
    labelMap,
    mandatoryIndexes,
    selectiveIndexes,
    pseudonym,
  } = await createDisclosureData(document, proof, options.selectivePointers, options)
  return serializeDerivedProofValue({
    bbsProof,
    labelMap,
    mandatoryIndexes,
    selectiveIndexes,
    presentationHeader: options.presentationHeader ? format.hexToBytes(options.presentationHeader) : new Uint8Array(),
    feature: options.feature,
    pseudonym,
    nymDomain: options.nymDomain ? format.hexToBytes(options.nymDomain) : undefined,
    lengthBBSMessages: options.lengthBBSMessages,
  })
}

/**
 * Verify a data integrity proof given a secured data document.
 *
 * @param {JsonLdObject} unsecuredDocument An unsecured input document to verify the selective disclosed signature.
 * @param {Proof} proof A selective disclosed signature to verify.
 * @param {object} options A set of options to use when verifying the selective disclosed signature.
 *
 * @see https://www.w3.org/TR/vc-di-ecdsa/#verify-derived-proof-ecdsa-sd-2023
 */
export async function verify(
  unsecuredDocument: JsonLdObject,
  proof: Proof,
  options: {
    curve: Curve
    documentLoader: LoadDocumentCallback
  },
): Promise<boolean> {
  // Procedure:
  //
  // 4. Initialize `bbsProof`, `proofHash`, `mandatoryHash`, `selectiveIndexes`, `presentationHeader`, `nonMandatory`,
  //    `featureOption`, and, possibly, `lengthBBSMessages` and/or `pseudonym`, to the values associated with their
  //    property names in the object returned when calling the `createVerifyData` function, passing the
  //    `unsecuredDocument`, `proof`, and any custom JSON-LD API options (such as a document loader).
  // 5. Initialize `bbsHeader` to the concatenation of `proofHash` and `mandatoryHash` in that order. Initialize
  //    `disclosedMessages` to an array of byte arrays obtained from the UTF-8 encoding of the elements of the
  //    `nonMandatory` array.
  // 6. Initialize `verified` to the result of applying the verification algorithm below, depending on the
  //    `featureOption` value.
  //
  //    6.1. If the `featureOption` equals `baseline`, initialize `verified` to the result of applying the verification
  //         algorithm `ProofVerify(PK, proof, header, ph, disclosed_messages, disclosed_indexes)` of [CFRG-BBS-
  //         SIGNATURE] with `PK` set as the public key of the original issuer, `proof` set as `bbsProof`, `header` set
  //         as `bbsHeader`, `disclosed_messages` set as `disclosedMessages`, `ph` set as `presentationHeader`, and
  //         `disclosed_indexes` set as `selectiveIndexes`.
  //    6.2. If the `featureOption` equals `anonymous_holder_binding`, initialize `verified` to the result of applying
  //         the `ProofVerify` verification algorithm of [CFRG-Blind-BBS-Signature] using `lengthBBSMessages` for the
  //         `L` parameter.
  //    6.3. If the `featureOption` equals `pseudonym` or `holder_binding_pseudonym`, initialize `verified` to the
  //         result of applying the `Proof Verification with Pseudonym` operation from [CFRG-Pseudonym-BBS-Signature]
  //         using `lengthBBSMessages` for the `L` parameter and an empty `committed_messages` array.

  // const {
  //   baseSignature,
  //   proofHash,
  //   publicKey,
  //   signatures,
  //   nonMandatory,
  //   mandatoryHash,
  // } = await createVerifyData(unsecuredDocument, proof, options)

  // if (signatures.length !== nonMandatory.length) {
  //   throw new ProcessingError(
  //     ProcessingErrorCode.PROOF_VERIFICATION_ERROR,
  //     "suite/core#verifySd",
  //     `The signature count ${signatures.length} does not match the non-mandatory message count ${nonMandatory.length}.`,
  //   )
  // }

  // const method = await document.retrieveVerificationMethod(
  //   proof.verificationMethod!,
  //   new Set(),
  //   { documentLoader: options.documentLoader },
  // )
  // const keypair = await ECKeypair.import(method, { curve: options.curve })
  // if (!keypair.publicKey) {
  //   throw new ProcessingError(
  //     ProcessingErrorCode.INVALID_VERIFICATION_METHOD,
  //     "suite/core#verifySd",
  //     "The specified verification method does not contain a public key.",
  //   )
  // }

  // const algorithm = curveToDigestAlgorithm(options.curve)
  // const toVerify = serializeSignData(proofHash, publicKey, mandatoryHash)

  // let verified: boolean = true
  // const verificationCheck = await crypto.subtle.verify(
  //   { name: SUITE_CONSTANT.ALGORITHM, hash: algorithm },
  //   keypair.publicKey,
  //   baseSignature,
  //   toVerify,
  // )
  // if (!verificationCheck) {
  //   verified = false
  // }

  // const localCurve = Curve.P256
  // const localAlgorithm = curveToDigestAlgorithm(localCurve)
  // const publicKeyMultibase = multi.base58btc.encode(publicKey)
  // const publicKeyMaterial = multibaseToMaterial(publicKeyMultibase, "public", localCurve)
  // const publicCryptoKey = await materialToPublicKey(publicKeyMaterial, localCurve)

  // const verificationChecks = await Promise.all(signatures.map((signature, index) =>
  //   crypto.subtle.verify(
  //     { name: SUITE_CONSTANT.ALGORITHM, hash: localAlgorithm },
  //     publicCryptoKey,
  //     signature,
  //     new TextEncoder().encode(nonMandatory[index]),
  //   )
  // ))

  // if (verificationChecks.includes(false)) {
  //   verified = false
  // }

  // return verified
}

type TransformedDocument = {
  mandatoryPointers: Array<string>
  mandatory: Map<number, string>
  nonMandatory: Map<number, string>
  hmacKey: Uint8Array
}

type HashData = {
  proofHash: Uint8Array
  mandatoryHash: Uint8Array
} & TransformedDocument
