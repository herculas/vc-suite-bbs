import { DIDURL, Keypair, URI, type VerificationResult } from "@crumble-jon/ld-crypto-syntax"

import * as KEYPAIR_CONSTANT from "./constants.ts"
import { Algorithm, generateKeypair, materialToMultibase } from "./core.ts"

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
   * The BBS algorithm.
   */
  algorithm: Algorithm

  /**
   * Generate a BLS12-381 keypair for BBS signatures.
   *
   * @param {Algorithm} algorithm The algorithm to use for keypair generation.
   * @param {URI} [_id] The identifier of the keypair.
   * @param {DIDURL} [_controller] The controller of the keypair.
   * @param {Date} [_revoked] The date and time when the keypair has been revoked.
   */
  constructor(algorithm: Algorithm, _id?: URI, _controller?: DIDURL, _revoked?: Date) {
    super(KEYPAIR_CONSTANT.TYPE_BASIC, _id, _controller, _revoked)
    this.algorithm = algorithm
  }

  /**
   * Initialize a BLS12-381 keypair for BBS signatures, generating the public and private key material encoded in
   * multibase format.
   *
   * @param {Uint8Array} [seed] The seed to use for keypair generation.
   */
  override async initialize(seed?: Uint8Array) {
    const { secretKey, publicKey } = generateKeypair(this.algorithm, seed)
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

  // override export(_options: DIDURL): Promise<DIDURL> {

  // }

  // static override import(_document: DIDURL, _options: DIDURL): Promise<Keypair> {

  // }

  /**
   * Calculate the public key multibase encoded string.
   *
   * @returns {string} The multibase encoded public key string.
   */
  private getPublicKeyMultibase(): string {
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
  private getPrivateKeyMultibase(): string {
    // TODO: throw encapsulated error
    if (!this.privateKey) {
      throw new Error("Private key not set")
    }
    return materialToMultibase(this.privateKey, "private")
  }
}
