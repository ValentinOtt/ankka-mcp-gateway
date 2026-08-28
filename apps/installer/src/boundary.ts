import * as v from 'valibot';

export type JsonPrimitive = boolean | null | number | string;

export interface JsonObject {
  readonly [key: string]: JsonValue;
}

export interface JsonArray extends ReadonlyArray<JsonValue> {}

export type JsonValue = JsonArray | JsonObject | JsonPrimitive;

/** Values accepted at untrusted Worker and provider boundaries before normalization. */
export interface BoundaryObject {
  readonly [key: string]: BoundaryValue;
}

export interface BoundaryArray extends ReadonlyArray<BoundaryValue> {}

export type BoundaryValue = BoundaryArray | BoundaryObject | JsonPrimitive | undefined;

export const jsonValueSchema: v.GenericSchema<JsonValue> = v.lazy(() => v.union([
  v.boolean(),
  v.null(),
  v.number(),
  v.string(),
  v.array(jsonValueSchema),
  v.record(v.string(), jsonValueSchema),
]));

export const boundaryValueSchema: v.GenericSchema<BoundaryValue> = v.lazy(() => v.union([
  v.boolean(),
  v.null(),
  v.number(),
  v.string(),
  v.undefined(),
  v.array(boundaryValueSchema),
  v.record(v.string(), boundaryValueSchema),
]));

export const boundaryObjectSchema: v.GenericSchema<BoundaryObject> = v.record(
  v.string(),
  boundaryValueSchema,
);
