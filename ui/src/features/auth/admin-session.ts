import type { FetchResponse } from '@fgrzl/fetch';
import {
  currentRoute,
  navigate,
  type RouteAuthState,
} from '@askrjs/askr/router';
import { adminApi } from '../../adapters';
import type {
  AdminLoginRequest,
  AdminSessionResponse,
} from '../../adapters/api.g';
import { isUnauthorized, unwrapResponse } from '../../adapters/response';

export type AdminSession = AdminSessionResponse;

export type AdminUser = {
  name: string;
  mode: AdminSession['mode'];
};

export async function loginAdminSession(
  credentials: AdminLoginRequest,
  signal?: AbortSignal
): Promise<void> {
  unwrapResponse(await adminApi.loginAdminSession(credentials, { signal }));
}

export async function logoutAdminSession({
  signal,
}: {
  signal?: AbortSignal;
} = {}): Promise<void> {
  unwrapResponse(await adminApi.logoutAdminSession({ signal }));
}

export async function loadAdminSession({
  signal,
}: {
  signal?: AbortSignal;
} = {}): Promise<AdminSession> {
  return unwrapResponse(await adminApi.getAdminSession({ signal }));
}

function currentLocationFromRoute(): string {
  const route = currentRoute();
  const routeQuery = route.query.toJSON();
  const query = new URLSearchParams();
  for (const [key, value] of Object.entries(routeQuery)) {
    if (Array.isArray(value)) {
      for (const item of value) {
        query.append(key, item);
      }
      continue;
    }

    query.append(key, value);
  }

  const search = query.toString();
  const hash = route.hash ? `#${route.hash}` : '';
  return `${route.path}${search ? `?${search}` : ''}${hash}`;
}

export function unwrapProtectedResponse<T>(response: FetchResponse<T>): T {
  try {
    return unwrapResponse(response);
  } catch (error) {
    if (isUnauthorized(error) && /^\/admin(?:\/|$)/.test(currentRoute().path)) {
      const next = currentLocationFromRoute();
      navigate(`/auth?next=${encodeURIComponent(next)}`, {
        history: 'replace',
      });
    }

    throw error;
  }
}

export async function resolveAdminSession({
  signal,
}: {
  signal: AbortSignal;
}): Promise<RouteAuthState<AdminSession, AdminUser>> {
  try {
    const session = await loadAdminSession({ signal });
    return {
      session,
      user: {
        name: session.username ?? 'Local administrator',
        mode: session.mode,
      },
    };
  } catch (error) {
    if (isUnauthorized(error)) {
      return { session: null, user: null };
    }

    throw error;
  }
}
