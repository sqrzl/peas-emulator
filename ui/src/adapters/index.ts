import { FetchClient } from '@fgrzl/fetch';
import { createAdapter } from './api.g';

export const adminApiPath = '/admin/v1';
export const adminApiBaseUrl = new URL(
  '/',
  globalThis.location?.origin ?? 'http://localhost'
).toString();

export const apiClient = new FetchClient({
  baseUrl: adminApiBaseUrl,
  credentials: 'same-origin',
});

export const adminApi = createAdapter(apiClient);

export default adminApi;
