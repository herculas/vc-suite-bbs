import { type LabelMap, ProcessingError, ProcessingErrorCode } from "@herculas/vc-data-integrity"
import * as PREFIX_CONSTANT from "../constant/prefix.ts"
import type { CompressedLabelMap } from "./types.ts"

/**
 * Compress a label map.
 *
 * @param {LabelMap} labelMap A label map to compress.
 *
 * @returns {CompressedLabelMap} A compressed label map.
 *
 * @see https://www.w3.org/TR/vc-di-bbs/#compresslabelmap
 */
export function compressLabelMap(labelMap: LabelMap): CompressedLabelMap {
  // Procedure:
  //
  // 1. Initialize `map` to an empty map.
  // 2. For each entry (`k`, `v`) in `labelMap`, do:
  //
  //    2.1. Add an entry to `map` with a key that is a base-10 integer parsed from the characters following the "c14n"
  //         prefix in `k`, and a value that is a base-10 integer parsed from the characters following the "b" prefix in
  //         `v`.
  //
  // 3. Return `map` as compressed label map.

  const map: CompressedLabelMap = new Map()
  for (const [key, value] of labelMap.entries()) {
    if (!key.startsWith(PREFIX_CONSTANT.BLANK_LABEL)) {
      throw new ProcessingError(
        ProcessingErrorCode.PROOF_GENERATION_ERROR,
        "suite/core#compressLabelMap",
        "The label map key contains an illegal prefix.",
      )
    }
    if (!value.startsWith(PREFIX_CONSTANT.COMPRESSED_VALUE)) {
      throw new ProcessingError(
        ProcessingErrorCode.PROOF_GENERATION_ERROR,
        "suite/core#compressLabelMap",
        "The label map value contains an illegal prefix.",
      )
    }

    const index = parseInt(key.replace(PREFIX_CONSTANT.BLANK_LABEL, ""), 10)
    const data = parseInt(value.replace(PREFIX_CONSTANT.COMPRESSED_VALUE, ""), 10)

    if (isNaN(index) || isNaN(data)) {
      throw new ProcessingError(
        ProcessingErrorCode.PROOF_GENERATION_ERROR,
        "suite/core#compressLabelMap",
        "The key or value of the label map MUST be a valid integer.",
      )
    }

    map.set(index, data)
  }
  return map
}

/**
 * Decompress a label map.
 *
 * @param {CompressedLabelMap} compressedLabelMap A compressed label map.
 *
 * @returns {LabelMap} A decompressed label map.
 *
 * @see https://www.w3.org/TR/vc-di-bbs/#decompresslabelmap
 */
export function decompressLabelMap(compressedLabelMap: CompressedLabelMap): LabelMap {
  // Procedure:
  //
  // 1. Initialize `map` to an empty map.
  // 2. For each entry (`k`, `v`) in `compressedLabelMap`, do:
  //
  //    2.1. Add an entry to `map` with a key that adds the prefix "c14n" to `k` and a value that adds a prefix "b" to
  //         `v`.
  //
  // 3. Return `map` as decompressed label map.

  const map: LabelMap = new Map()
  for (const [key, value] of compressedLabelMap.entries()) {
    const index = `${PREFIX_CONSTANT.BLANK_LABEL}${key}`
    const data = `${PREFIX_CONSTANT.COMPRESSED_VALUE}${value}`
    map.set(index, data)
  }
  return map
}
