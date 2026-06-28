import type { FetchResponse } from '@fgrzl/fetch';
import { navigate, type RouteAuthState } from '@askrjs/askr/router';
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

export function isDevAuthBypassed(): boolean {
  return (
    import.meta.env.MODE === 'development' &&
    import.meta.env.VITE_REQUIRE_ADMIN_AUTH !== 'true'
  );
}

function localDevelopmentSession(): AdminSession {
  return {
    mode: 'open',
    username: 'local-development',
  };
}

export async function loginAdminSession(
  credentials: AdminLoginRequest,
  signal?: AbortSignal
): Promise<void> {
  if (isDevAuthBypassed()) {
    return;
  }

  unwrapResponse(await adminApi.loginAdminSession(credentials, { signal }));
}

export async function logoutAdminSession({
  signal,
}: {
  signal?: AbortSignal;
} = {}): Promise<void> {
  if (isDevAuthBypassed()) {
    return;
  }

  unwrapResponse(await adminApi.logoutAdminSession({ signal }));
}

export async function loadAdminSession({
  signal,
}: {
  signal?: AbortSignal;
} = {}): Promise<AdminSession> {
  if (isDevAuthBypassed()) {
    return localDevelopmentSession();
  }

  return unwrapResponse(await adminApi.getAdminSession({ signal }));
}

function currentLocationFromWindow(): string {
  if (typeof window === 'undefined') {
    return '/';
  }

  return `${window.location.pathname}${window.location.search}${window.location.hash}`;
}

export function unwrapProtectedResponse<T>(response: FetchResponse<T>): T {
  try {
    return unwrapResponse(response);
  } catch (error) {
    if (
      !isDevAuthBypassed() &&
      isUnauthorized(error) &&
      typeof window !== 'undefined' &&
      /^\/admin(?:\/|$)/.test(window.location.pathname)
    ) {
      const next = currentLocationFromWindow();
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
  if (isDevAuthBypassed()) {
    const session = localDevelopmentSession();
    return {
      session,
      user: {
        name: 'Local development',
        mode: session.mode,
      },
    };
  }

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
