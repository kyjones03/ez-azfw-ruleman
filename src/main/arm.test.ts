import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const mocks = vi.hoisted(() => ({ token: vi.fn(), fetch: vi.fn() }));
vi.mock('./auth', () => ({ getCredential: () => ({ getToken: mocks.token }) }));
const { armRequest, armList, armWrite } = await import('./arm');

beforeEach(() => {
  vi.resetAllMocks();
  mocks.token.mockResolvedValue({ token: 'test-token' });
  vi.stubGlobal('fetch', mocks.fetch);
});
afterEach(() => {
  vi.unstubAllGlobals();
  vi.useRealTimers();
});

describe('shared ARM transport', () => {
  it('never sends ARM credentials to another origin', async () => {
    await expect(armRequest('https://example.com/operation')).rejects.toThrow(
      'unexpected',
    );
    expect(mocks.token).not.toHaveBeenCalled();
    expect(mocks.fetch).not.toHaveBeenCalled();
  });

  it('uses the ARM scope, preserves caller headers and surfaces Azure errors', async () => {
    mocks.fetch.mockResolvedValueOnce(
      new Response(JSON.stringify({ value: 1 }), { status: 200 }),
    );
    await expect(
      armRequest('/resource', { headers: { 'If-Match': 'etag' } }),
    ).resolves.toMatchObject({ data: { value: 1 } });
    expect(mocks.token).toHaveBeenCalledWith(
      'https://management.azure.com/.default',
    );
    const init = mocks.fetch.mock.calls[0][1] as RequestInit;
    expect(new Headers(init.headers).get('If-Match')).toBe('etag');
    expect(init.redirect).toBe('error');
    mocks.fetch.mockResolvedValueOnce(
      new Response(
        JSON.stringify({
          error: { code: 'AuthorizationFailed', message: 'Denied' },
        }),
        { status: 403 },
      ),
    );
    await expect(armRequest('/resource')).rejects.toMatchObject({
      code: 'AuthorizationFailed',
      statusCode: 403,
      message: 'Denied',
    });
  });

  it('reads all pages but rejects an external next link without fetching it', async () => {
    mocks.fetch
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            value: [1],
            nextLink: 'https://management.azure.com/page2',
          }),
        ),
      )
      .mockResolvedValueOnce(new Response(JSON.stringify({ value: [2] })));
    await expect(armList('/page1')).resolves.toEqual([1, 2]);
    mocks.fetch
      .mockClear()
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({ value: [1], nextLink: 'https://example.com/page2' }),
        ),
      );
    await expect(armList('/page1')).rejects.toThrow('unexpected');
    expect(mocks.fetch).toHaveBeenCalledTimes(1);
  });

  it('waits for the actual long-running operation outcome', async () => {
    vi.useFakeTimers();
    mocks.fetch
      .mockResolvedValueOnce(
        new Response('{}', {
          status: 202,
          headers: {
            'azure-asyncoperation':
              'https://management.azure.com/operations/test',
          },
        }),
      )
      .mockResolvedValueOnce(
        new Response(JSON.stringify({ status: 'InProgress' })),
      )
      .mockResolvedValueOnce(
        new Response(JSON.stringify({ status: 'Succeeded' })),
      );
    const operation = armWrite('/firewall', 'PUT', {
      properties: { enabled: true },
    });
    await vi.runAllTimersAsync();
    await operation;
    expect(mocks.fetch).toHaveBeenCalledTimes(3);
  });

  it('does not return success for invalid JSON or an untrackable accepted write', async () => {
    mocks.fetch.mockResolvedValueOnce(new Response('not json'));
    await expect(armRequest('/resource')).rejects.toThrow('invalid JSON');
    mocks.fetch.mockResolvedValueOnce(new Response('{}', { status: 202 }));
    await expect(armWrite('/firewall', 'PUT', {})).rejects.toThrow(
      'status endpoint',
    );
  });

  it('preserves nested Azure codes on an accepted operation that later fails without resubmitting', async () => {
    vi.useFakeTimers();
    mocks.fetch
      .mockResolvedValueOnce(
        new Response('{}', {
          status: 200,
          headers: { 'azure-asyncoperation': '/operations/start' },
        }),
      )
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            status: 'Failed',
            error: {
              code: 'ResourceOperationFailure',
              message: 'The resource operation failed.',
              details: [
                {
                  code: 'PreconditionFailed',
                  message: 'Precondition failed.',
                },
              ],
            },
          }),
        ),
      );
    const operation = armWrite('/firewall', 'PUT', {});
    const assertion = expect(operation).rejects.toMatchObject({
      code: 'ResourceOperationFailure',
      operationStatus: 'failed',
      message:
        'The resource operation failed. PreconditionFailed: Precondition failed.',
    });
    await vi.runAllTimersAsync();
    await assertion;
    expect(mocks.fetch).toHaveBeenCalledTimes(2);
    expect(mocks.fetch.mock.calls.map(([, init]) => init.method)).toEqual([
      'PUT',
      undefined,
    ]);
  });

  it('keeps direct HTTP precondition failures distinct from accepted-operation failures', async () => {
    mocks.fetch.mockResolvedValueOnce(
      new Response(
        JSON.stringify({
          error: {
            code: 'PreconditionFailed',
            message: 'The resource changed.',
            details: [
              { code: 'EtagMismatch', message: 'Refresh before retrying.' },
            ],
          },
        }),
        { status: 412 },
      ),
    );
    await expect(
      armWrite('/firewall', 'PUT', {}, 'old-etag'),
    ).rejects.toMatchObject({
      code: 'PreconditionFailed',
      statusCode: 412,
      message: 'The resource changed. EtagMismatch: Refresh before retrying.',
    });
    expect(mocks.fetch).toHaveBeenCalledTimes(1);
  });
});
