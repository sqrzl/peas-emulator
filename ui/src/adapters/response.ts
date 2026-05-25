import type { FetchResponse } from '@fgrzl/fetch';
import type { ErrorResponse } from './api.g';

export class AdminApiError extends Error {
  readonly status: number;
  readonly code?: string;

  constructor(message: string, status: number, code?: string) {
    super(message);
    this.name = 'AdminApiError';
    this.status = status;
    this.code = code;
  }
}

export function unwrapResponse<T>(response: FetchResponse<T>): T {
  if (response.ok) {
    return response.data;
  }

  const body = response.error.body as Partial<ErrorResponse> | undefined;
  const message =
    body?.details?.trim() ||
    body?.error?.trim() ||
    response.error.message ||
    response.statusText ||
    'Request failed';

  throw new AdminApiError(message, response.status, body?.code);
}

export function isUnauthorized(error: unknown): boolean {
  return error instanceof AdminApiError && error.status === 401;
}
