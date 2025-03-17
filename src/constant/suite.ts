import type { Flag } from "@herculas/vc-data-integrity"

export const JWK_TYPE = "EC"
export const JWK_USE = "sig"
export const ALGORITHM = "BLS12_381G2"

export const KEYPAIR_DOCUMENT_TYPE_MULTI = "Multikey"
export const KEYPAIR_DOCUMENT_TYPE_JWK = "JsonWebKey"

export const KEYPAIR_TYPE = "Bls12381G2Key2020"
export const GENERAL_PROOF_TYPE = "DataIntegrityProof"
export const SUITE_BBS = "bbs-2023"

export const KEY_MATERIAL_LENGTH: Map<Flag, number> = new Map([
  ["public", 96],
  ["private", 32],
])

export const MINIMAL_SEED_LENGTH = 32
