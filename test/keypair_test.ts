import { assert, assertEquals } from "@std/assert"
import { generateKeypair, materialToMultibase, multibaseToMaterial } from "../src/keypair/core.ts"
import { BBSKeypair } from "../src/keypair/keypair.ts"

Deno.test("raw keypair generation", () => {
  const { secretKey, publicKey } = generateKeypair("BLS12_381_G1_XOF_SHAKE_256")
  const privateMulti = materialToMultibase(secretKey, "private")
  const publicMulti = materialToMultibase(publicKey, "public")

  const decodedPrivate = multibaseToMaterial(privateMulti, "private")
  const decodedPublic = multibaseToMaterial(publicMulti, "public")

  assertEquals(secretKey, decodedPrivate)
  assertEquals(publicKey, decodedPublic)
})

Deno.test("keypair fingerprint", async () => {
  const keypair = new BBSKeypair("BLS12_381_G1_XOF_SHAKE_256")
  await keypair.initialize()

  const fingerprint = await keypair.generateFingerprint()
  const result = await keypair.verifyFingerprint(fingerprint)

  assert(result)
})

Deno.test("jwk export", async () => {
  const keypair = new BBSKeypair("BLS12_381_G1_XOF_SHAKE_256")
  keypair.controller = "did:example:1145141919810"
  await keypair.initialize()

  const jwkPrivate = await keypair.export({ type: "jwk", flag: "private" })
  const jwkPublic = await keypair.export({ type: "jwk", flag: "public" })
  
  console.log(jwkPrivate)
  console.log(jwkPublic)
})
