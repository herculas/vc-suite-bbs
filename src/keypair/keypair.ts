import {
  DIDURL,
  Keypair,
  KeypairDocument,
  KeypairExportOptions,
  KeypairImportOptions,
  URI,
  type VerificationResult,
} from "@crumble-jon/ld-crypto-syntax"

import { Algorithm, generateKeypair, keypairToJwk, materialToMultibase } from "./core.ts"

export class BBSKeypair extends Keypair {
  /**
   * The BBS public key.
   */
  publicKey?: Uint8Array

  /**
   * The BBS private key.
   */
  privateKey?: Uint8Array

  /**
   * Generate a BLS12-381 keypair for BBS signatures.
   *
   * @param {Algorithm} algorithm The algorithm to use for keypair generation.
   * @param {URI} [_id] The identifier of the keypair.
   * @param {DIDURL} [_controller] The controller of the keypair.
   * @param {Date} [_revoked] The date and time when the keypair has been revoked.
   */
  constructor(algorithm: Algorithm, _id?: URI, _controller?: DIDURL, _revoked?: Date) {
    super(algorithm, _id, _controller, _revoked)
  }

  /**
   * Initialize a BLS12-381 keypair for BBS signatures, generating the public and private key material encoded in
   * multibase format.
   *
   * @param {Uint8Array} [seed] The seed to use for keypair generation.
   */
  override async initialize(seed?: Uint8Array) {
    const { secretKey, publicKey } = generateKeypair(this.type as Algorithm, seed)
    this.privateKey = secretKey
    this.publicKey = publicKey

    // set the identifier if controller is specified
    if (this.controller && !this.id) {
      this.id = `${this.controller}#${await this.generateFingerprint()}`
    }
  }

  /**
   * Calculate the public key fingerprint, multibase + multicodec encoded. The specific fingerprint method is determined
   * by the key suite, and is often either a hash of the public key material, or the full encoded public key. This
   * method is frequently used to initialize the key identifier or generate some types of cryptonym DIDs.
   */
  override generateFingerprint(): Promise<string> {
    return Promise.resolve(this.getPublicKeyMultibase())
  }

  /**
   * Verify that a provided fingerprint matches the fingerprint of the public key.
   *
   * @param {string} fingerprint A public key fingerprint.
   *
   * @returns {Promise<VerificationResult>} Resolve to a verification result indicating whether the fingerprint matches
   * this keypair instance.
   */
  override async verifyFingerprint(fingerprint: string): Promise<VerificationResult> {
    // TODO: encapsulated error
    if (fingerprint !== await this.generateFingerprint()) {
      return Promise.resolve({
        verified: false,
        errors: new Error("Fingerprint does not match public key"),
      })
    }
    return Promise.resolve({
      verified: true,
    })
  }

  /**
   * Export the serialized representation of the keypair, along with other metadata which can be used to form a proof.
   *
   * @param {KeypairExportOptions} options The options to export the keypair.
   *
   * @returns {Promise<KeypairDocument>} Resolve to a serialized keypair to be exported.
   */
  override async export(options: KeypairExportOptions): Promise<KeypairDocument> {
    if (!options.flag) {
      options.flag = "public"
    }

    // TODO: encapsulated error
    if ((options.flag === "private" && !this.privateKey) || (options.flag === "public" && !this.publicKey)) {
      throw new Error("Key material not set")
    }

    // TODO: encapsulated error
    if (!this.id || !this.controller) {
      throw new Error("Identifier not set")
    }

    if (options.type === "jwk") {
      return await keypairToJwk(this, options.flag)
    } else if (options.type === "multibase") {
      throw new Error("Not implemented")
    } else {
      throw new Error("Invalid export type")
    }
  }

   /**
   * Import a keypair from a serialized representation of a keypair.
   *
   * @param {KeypairDocument} document An externally fetched key document.
   * @param {KeypairImportOptions} options Options for keypair import.
   *
   * @returns {Promise<BBSKeypair>} Resolve to a keypair instance.
   */
  static override import(document: KeypairDocument, options: KeypairImportOptions): Promise<BBSKeypair> {
    
  }

  /**
   * Calculate the public key multibase encoded string.
   *
   * @returns {string} The multibase encoded public key string.
   */
  getPublicKeyMultibase(): string {
    // TODO: throw encapsulated error
    if (!this.publicKey) {
      throw new Error("Public key not set")
    }
    return materialToMultibase(this.publicKey, "public")
  }

  /**
   * Calculate the private key multibase encoded string.
   *
   * @returns {string} The multibase encoded private key string.
   */
  getPrivateKeyMultibase(): string {
    // TODO: throw encapsulated error
    if (!this.privateKey) {
      throw new Error("Private key not set")
    }
    return materialToMultibase(this.privateKey, "private")
  }
}
