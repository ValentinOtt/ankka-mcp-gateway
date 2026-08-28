import * as v from 'valibot';

const objectContainerSchema = v.object({});

/**
 * Validate an acyclic plain JSON-like data tree without invoking getters,
 * proxies aside. Arrays must be dense and objects may contain only enumerable
 * own data properties with string keys.
 */
export function isPlainDataTree<Value>(value: Value): boolean {
  return validatePlainDataTree(value, new WeakSet<object>(), new WeakSet<object>());
}

function validatePlainDataTree<Value>(
  value: Value,
  active: WeakSet<object>,
  validated: WeakSet<object>,
): boolean {
  if (value === null || v.is(v.string(), value) || v.is(v.boolean(), value)) return true;
  if (v.is(v.number(), value)) return Number.isFinite(value);
  if (!v.is(objectContainerSchema, value)) return false;
  if (validated.has(value)) return true;
  if (active.has(value)) return false;
  active.add(value);
  try {
    const array = Array.isArray(value);
    if ((array && Object.getPrototypeOf(value) !== Array.prototype) ||
        (!array && Object.getPrototypeOf(value) !== Object.prototype)) return false;
    const keys = Reflect.ownKeys(value);
    if (keys.some((key) => v.is(v.symbol(), key))) return false;
    const descriptors = Object.getOwnPropertyDescriptors(value);
    if (array) {
      const lengthDescriptor = descriptors.length;
      if (!lengthDescriptor || lengthDescriptor.value !== value.length || keys.length !== value.length + 1) {
        return false;
      }
      for (let index = 0; index < value.length; index += 1) {
        const descriptor = descriptors[String(index)];
        if (!descriptor || descriptor.enumerable !== true || !Object.hasOwn(descriptor, 'value') ||
            !validatePlainDataTree(descriptor.value, active, validated)) return false;
      }
    } else {
      for (const key of keys) {
        if (!v.is(v.string(), key)) return false;
        const descriptor = descriptors[key];
        if (!descriptor || descriptor.enumerable !== true || !Object.hasOwn(descriptor, 'value') ||
            !validatePlainDataTree(descriptor.value, active, validated)) return false;
      }
    }
    validated.add(value);
    return true;
  } catch {
    return false;
  } finally {
    active.delete(value);
  }
}

/** Deep-freeze a value already accepted by {@link isPlainDataTree}. */
export function deepFreezePlainData<Value>(value: Value): Value {
  if (!isPlainDataTree(value)) throw new TypeError('Value is not a plain data tree');
  freezePlainData(value, new WeakSet<object>());
  return value;
}

function freezePlainData<Value>(value: Value, frozen: WeakSet<object>): void {
  if (!v.is(objectContainerSchema, value) || frozen.has(value)) return;
  frozen.add(value);
  for (const key of Reflect.ownKeys(value)) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor && Object.hasOwn(descriptor, 'value')) freezePlainData(descriptor.value, frozen);
  }
  Object.freeze(value);
}
