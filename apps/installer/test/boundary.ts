import * as v from 'valibot';

/** Parse JSON returned by a test HTTP boundary with the endpoint's exact schema. */
export async function responseJson<Schema extends v.GenericSchema>(
  response: Response,
  schema: Schema,
): Promise<v.InferOutput<Schema>> {
  return v.parse(schema, await response.json());
}

/** Parse JSON submitted to a test HTTP boundary with the endpoint's exact schema. */
export async function requestJson<Schema extends v.GenericSchema>(
  request: { json(): Promise<v.InferInput<Schema>> },
  schema: Schema,
): Promise<v.InferOutput<Schema>> {
  return v.parse(schema, await request.json());
}
