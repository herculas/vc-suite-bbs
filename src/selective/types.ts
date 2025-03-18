import type { JsonValue, LabelMap, NQuad } from "@herculas/vc-data-integrity"
import type { Feature } from "../constant/feature.ts"

export type CompressedLabelMap = Map<number, number>

export type BaseProofValue = {
  bbsSignature: Uint8Array
  bbsHeader: Uint8Array
  publicKey: Uint8Array
  hmacKey: Uint8Array
  mandatoryPointers: Array<string>
  feature: Feature
  signerNymEntropy?: Uint8Array
}

export type CompressedProofValue = {
  bbsProof: Uint8Array
  compressedLabelMap: CompressedLabelMap
  mandatoryIndexes: Array<number>
  selectiveIndexes: Array<number>
  presentationHeader: Uint8Array
  feature: Feature
  nymDomain?: Uint8Array
  pseudonym?: Uint8Array
  lengthBBSMessages?: number
}

export type DerivedProofValue = {
  bbsProof: Uint8Array
  labelMap: LabelMap
  mandatoryIndexes: Array<number>
  selectiveIndexes: Array<number>
  presentationHeader: Uint8Array
  feature: Feature
  nymDomain?: Uint8Array
  pseudonym?: Uint8Array
  lengthBBSMessages?: number
}

export type DisclosureData = {
  bbsProof: Uint8Array
  labelMap: LabelMap
  mandatoryIndexes: Array<number>
  selectiveIndexes: Array<number>
  presentationHeader: Uint8Array
  revealDocument: JsonValue
  pseudonym?: Uint8Array
}

export type VerifyData = {
  bbsProof: Uint8Array
  proofHash: Uint8Array
  mandatoryHash: Uint8Array
  selectiveIndexes: Array<number>
  presentationHeader: Uint8Array
  nonMandatory: Array<NQuad>
  feature: Feature
  pseudonym?: Uint8Array
  lengthBBSMessages?: number
}

// basic                                   blind                                       nym
//    sign:
//        - secret key: string (64)          - commitmentWithProof?: string              - commitmentWithProof?: string
//        - public key: string (192)                                                     - signerNymEntropy?: string (64)
//        - header?: string
//        - messages?: string[]
//        - cipher: Cipher
//        o signature: string (160)
//    verify:
//        - public key: string (192)         - committedMessages?: string[]              - committedMessages?: string[]
//        - signature: string                - proverBlindness?: string (64)             - proverBlindness?: string (64)
//        - header?: string                                                              - proverNym?: string (64)
//        - messages?: string[]                                                          - signerNymEntropy?: string (64)
//        - cipher: Cipher
//        o valid: boolean
//    prove:
//        - public key: string               - committedMessages?: string[]              - committedMessages?: string[]
//        - signature: string                - disclosedCommittedIndexes?: number[]      - disclosedCommittedIndexes?: number[]
//        - header?: string                  - proverBlindness?: string (64)             - proverBlindness?: string (64)
//        - presentationHeader?: string                                                  - nymSecret?: string (64)
//        - messages?: string[]                                                          - contextId?: string
//        - disclosedIndexes?: number[]
//        - cipher: Cipher
//        o proof: string
//    validate:
//        - public key: string               - l: number                                 - l: number
//        - proof: string                    - disclosedCommittedMessages?: string[]     - disclosedCommittedMessages?: string[]
//        - header?: string                  - disclosedCommittedIndexes?: number[]      - disclosedCommittedIndexes?: number[]
//        - presentationHeader?: string                                                  - pseudonym?: string
//        - disclosedMessages?: string[]                                                 - contextId?: string
//        - disclosedIndexes?: number[]
//        - cipher: Cipher
//        o valid: boolean
