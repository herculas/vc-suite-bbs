import { Credential, Proof } from "@herculas/vc-data-integrity"

import { Bbs2023 } from "../src/suite/bbs.ts"
import { Feature } from "../src/constant/feature.ts"
import { testLoader } from "./mock/loader.ts"

import * as UNSECURED_CRED_1 from "./mock/unsecured-credential-1.json" with { type: "json" }
import * as PROOF_OPTIONS_1 from "./mock/proof-options-1.json" with { type: "json" }

Deno.test("BBS-2023: case 1", async () => {
  const unsecuredCredential = structuredClone(UNSECURED_CRED_1.default) as Credential
  const proofOptions = structuredClone(PROOF_OPTIONS_1.default) as Proof

  const mandatoryPointers = ["/issuer"]

  const proof = await Bbs2023.createProof(unsecuredCredential, {
    feature: Feature.BASELINE,
    proof: proofOptions,
    mandatoryPointers,
    documentLoader: testLoader,
  })

  console.log(proof)
})
