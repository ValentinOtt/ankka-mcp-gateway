/** Decode bounded, canonical module content without a release-sized regex stack. */
export function decodeWorkerModuleBase64(value: string, maximumByteLength: number): Uint8Array | null {
  if (value.length < 4 || value.length % 4 !== 0 ||
      value.length > 4 * Math.ceil(maximumByteLength / 3)) return null;
  try {
    const binary = atob(value);
    // atob accepts whitespace and noncanonical pad bits. The linear round trip
    // rejects those forms as well as missing padding before allocating bytes.
    if (binary.length < 1 || binary.length > maximumByteLength || btoa(binary) !== value) return null;
    return Uint8Array.from(binary, (character) => character.charCodeAt(0));
  } catch {
    return null;
  }
}
