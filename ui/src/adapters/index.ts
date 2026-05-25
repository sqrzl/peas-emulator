import { FetchClient } from '@fgrzl/fetch';

export const adminApiPath = '/admin/v1';
export const adminApiBaseUrl = new URL(
  adminApiPath,
  globalThis.location?.origin ?? 'http://localhost'
).toString();

export const api = new FetchClient({
  baseUrl: adminApiBaseUrl,
  credentials: 'same-origin',
});

export default api;
