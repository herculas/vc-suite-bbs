import { assert, assertEquals, assertExists } from "@std/assert"

import { Bls12381G2Keypair } from "../src/key/keypair.ts"
import { generateKeypair, jwkToMaterial, materialToJwk } from "../src/key/core.ts"

Deno.test("fingerprint generation and verification", async () => {
  const keypair = new Bls12381G2Keypair()
  await keypair.initialize()

  const fingerprint = await keypair.generateFingerprint()
  const result = await keypair.verifyFingerprint(fingerprint)

  assert(result)
})

Deno.test("Keypair import and export: raw functions", () => {
  const { publicKey, secretKey } = generateKeypair()

  const jwkPublic = materialToJwk(publicKey, "public")
  const jwkPrivate = materialToJwk(secretKey, "private")

  const recoveredPublic = jwkToMaterial(jwkPublic, "public")
  const recoveredPrivate = jwkToMaterial(jwkPrivate, "private")

  const jwkPrivate2 = materialToJwk(recoveredPrivate, "private")
  const jwkPublic2 = materialToJwk(recoveredPublic, "public")

  assertEquals(jwkPublic, jwkPublic2)
  assertEquals(jwkPrivate, jwkPrivate2)
})

Deno.test("keypair export: encapsulated", async () => {
  const keypair = new Bls12381G2Keypair()
  keypair.controller = "did:example:1145141919810"
  await keypair.initialize()

  const jwkPrivate = await keypair.export({ type: "JsonWebKey", flag: "private" })
  const jwkPublic = await keypair.export({ type: "JsonWebKey", flag: "public" })

  const multibasePrivate = await keypair.export({ type: "Multikey", flag: "private" })
  const multibasePublic = await keypair.export({ type: "Multikey", flag: "public" })

  assertExists(jwkPrivate)
  assertExists(jwkPublic)
  assertExists(multibasePrivate)
  assertExists(multibasePublic)
})

Deno.test("keypair export and import: JSON Web Key", async () => {
  const keypair = new Bls12381G2Keypair()
  keypair.controller = "did:example:1145141919810"
  await keypair.initialize()

  const jwkPrivate = await keypair.export({ type: "JsonWebKey", flag: "private" })
  const jwkPublic = await keypair.export({ type: "JsonWebKey", flag: "public" })

  const recoveredPublicOnly = await Bls12381G2Keypair.import(jwkPublic)
  const recoveredBoth = await Bls12381G2Keypair.import(jwkPrivate)

  assertExists(recoveredPublicOnly.publicKey)
  assertExists(recoveredBoth.privateKey)
  assertExists(recoveredBoth.publicKey)
})

Deno.test("keypair export and import: Multikey", async () => {
  const keypair = new Bls12381G2Keypair()
  keypair.controller = "did:example:1145141919810"
  await keypair.initialize()

  const multiPrivate = await keypair.export({ type: "Multikey", flag: "private" })
  const multiPublic = await keypair.export({ type: "Multikey", flag: "public" })

  const recoveredPublicOnly = await Bls12381G2Keypair.import(multiPublic)
  const recoveredBoth = await Bls12381G2Keypair.import(multiPrivate)

  assertExists(recoveredPublicOnly.publicKey)
  assertExists(recoveredBoth.privateKey)
  assertExists(recoveredBoth.publicKey)
})
