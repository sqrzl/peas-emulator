export type AdminCredentials = {
  username: string;
  password: string;
};

type ErrorBody = {
  error?: string;
  details?: string;
};

function requestOptions(signal?: AbortSignal): RequestInit {
  return {
    credentials: 'same-origin',
    signal,
  };
}

async function readAuthError(response: Response): Promise<string> {
  try {
    const body = (await response.json()) as ErrorBody;
    return body.details ?? body.error ?? 'Unable to complete the request.';
  } catch {
    return 'Unable to complete the request.';
  }
}

export async function loginAdminSession(
  credentials: AdminCredentials
): Promise<void> {
  const response = await fetch('/admin/v1/auth/login', {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
    },
    body: JSON.stringify(credentials),
    ...requestOptions(),
  });

  if (!response.ok) {
    throw new Error(await readAuthError(response));
  }
}

export async function logoutAdminSession({
  signal,
}: {
  signal?: AbortSignal;
} = {}): Promise<void> {
  const response = await fetch('/admin/v1/auth/logout', {
    method: 'POST',
    ...requestOptions(signal),
  });

  if (!response.ok) {
    throw new Error(await readAuthError(response));
  }
}
