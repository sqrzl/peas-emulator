export function prettyJson(value: unknown): string {
  return JSON.stringify(value, null, 2);
}

export function parseJson<T>(value: string): T {
  return JSON.parse(value) as T;
}
