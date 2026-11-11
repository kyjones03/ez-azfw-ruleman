import { getCredential } from './auth';

const ARM_ORIGIN = 'https://management.azure.com';

interface ArmError {
  code?: string;
  message?: string;
  details?: ArmError[];
}

function armError(error: ArmError | undefined, fallback: string): Error {
  const describeDetail = (detail: ArmError): string =>
    [
      [detail.code, detail.message].filter(Boolean).join(': '),
      ...(Array.isArray(detail.details)
        ? detail.details.map(describeDetail)
        : []),
    ]
      .filter(Boolean)
      .join(' ');
  return Object.assign(
    new Error(
      [
        error?.message || fallback,
        ...(Array.isArray(error?.details)
          ? error.details.map(describeDetail)
          : []),
      ]
        .filter(Boolean)
        .join(' '),
    ),
    { code: error?.code },
  );
}

/** Only ARM-origin URLs receive an ARM token, including next links and operation polling. */
export async function armRequest<T>(
  path: string,
  init: RequestInit = {},
): Promise<{ status: number; headers: Headers; data: T }> {
  const url = new URL(path, ARM_ORIGIN);
  if (url.origin !== ARM_ORIGIN || url.username || url.password)
    throw new Error('Azure returned an unexpected Resource Manager endpoint.');
  const token = await getCredential().getToken(`${ARM_ORIGIN}/.default`);
  if (!token?.token) throw new Error('Azure did not return an access token.');
  const headers = new Headers(init.headers);
  headers.set('Authorization', `Bearer ${token.token}`);
  headers.set('Content-Type', 'application/json');
  const response = await fetch(url.href, {
    ...init,
    headers,
    redirect: 'error',
    signal: AbortSignal.timeout(60_000),
  });
  const text = await response.text();
  let data: unknown;
  try {
    data = text ? JSON.parse(text) : {};
  } catch {
    if (response.ok)
      throw new Error('Azure returned an invalid JSON response.');
    data = { message: text };
  }
  if (!response.ok) {
    const body = data as ArmError & { error?: ArmError };
    const error = body?.error ?? body;
    throw Object.assign(
      armError(error, `Azure error (HTTP ${response.status}).`),
      { statusCode: response.status },
    );
  }
  return {
    status: response.status,
    headers: response.headers,
    data: data as T,
  };
}

export async function armList<T>(path: string): Promise<T[]> {
  const result: T[] = [];
  let next: string | undefined = path;
  while (next) {
    const response = await armRequest<{ value?: T[]; nextLink?: string }>(next);
    const data: { value?: T[]; nextLink?: string } = response.data;
    if (!Array.isArray(data.value))
      throw new Error('Azure returned an invalid resource list.');
    result.push(...data.value);
    next = data.nextLink;
  }
  return result;
}

export async function armWrite(
  path: string,
  method: 'PUT' | 'DELETE',
  body?: unknown,
  etag?: string,
): Promise<void> {
  const response = await armRequest<unknown>(path, {
    method,
    body: body === undefined ? undefined : JSON.stringify(body),
    headers: etag ? { 'If-Match': etag } : undefined,
  });
  const poll =
    response.headers.get('azure-asyncoperation') ??
    response.headers.get('operation-location') ??
    (response.status === 202 ? response.headers.get('location') : null);
  if (response.status === 202 && !poll)
    throw new Error(
      'Azure accepted an operation without returning a status endpoint. Refresh before retrying.',
    );
  if (!poll) return;
  const started = Date.now();
  for (;;) {
    if (Date.now() - started > 20 * 60_000)
      throw new Error(
        'Azure is still applying this operation after 20 minutes. Refresh to check its outcome before retrying.',
      );
    await new Promise((resolve) => setTimeout(resolve, 2000));
    const { data } = await armRequest<{
      status?: string;
      properties?: { provisioningState?: string };
      error?: ArmError;
    }>(poll);
    const state = (
      data.status ?? data.properties?.provisioningState
    )?.toLowerCase();
    if (state === 'succeeded') return;
    if (state === 'failed' || state === 'canceled' || state === 'cancelled')
      throw Object.assign(armError(data.error, `Azure operation ${state}.`), {
        operationStatus: state,
      });
    if (!state)
      throw new Error(
        'Azure returned an operation status without a state. Refresh before retrying.',
      );
  }
}
