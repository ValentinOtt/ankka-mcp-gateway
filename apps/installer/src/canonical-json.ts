import * as v from 'valibot';

const canonicalObjectSchema = v.record(v.string(), v.unknown());

/** Serialize a finite, acyclic plain JSON data tree with lexically sorted keys. */
export function canonicalJson<Value>(value: Value): string {
  return serializeCanonical(value, new Set<object>());
}

function serializeCanonical<Value>(value: Value, seen: Set<object>): string {
  if (value === null || v.is(v.string(), value) || v.is(v.boolean(), value)) {
    return JSON.stringify(value);
  }
  if (v.is(v.number(), value)) {
    if (!Number.isFinite(value)) throw new TypeError('Canonical JSON requires finite numbers');
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    if (seen.has(value)) throw new TypeError('Canonical JSON does not support cycles');
    seen.add(value);
    const serialized = `[${value.map((entry) => serializeCanonical(entry, seen)).join(',')}]`;
    seen.delete(value);
    return serialized;
  }
  if (v.is(canonicalObjectSchema, value) && Object.getPrototypeOf(value) === Object.prototype) {
    if (seen.has(value)) throw new TypeError('Canonical JSON does not support cycles');
    seen.add(value);
    const entries = Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${serializeCanonical(value[key], seen)}`);
    seen.delete(value);
    return `{${entries.join(',')}}`;
  }
  throw new TypeError('Canonical JSON supports only JSON values');
}
