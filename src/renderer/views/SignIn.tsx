import { useState } from 'react';
import { ChevronRight } from 'lucide-react';
import { Logo } from '../components/Logo';
import { Spinner } from '../components/ui';
import { errorMessage } from '../components/Toast';
import type { AccountInfo, AuthMethod } from '../../shared/types';

export function SignIn({
  onSignedIn,
}: {
  onSignedIn: (account: AccountInfo) => void;
}) {
  const [busy, setBusy] = useState<AuthMethod | null>(null);
  const [error, setError] = useState('');
  const [tenant, setTenant] = useState('');
  const [showTenant, setShowTenant] = useState(false);

  const signIn = async (method: AuthMethod) => {
    setBusy(method);
    setError('');
    try {
      onSignedIn(await window.api.signIn(method, tenant.trim() || undefined));
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(null);
    }
  };

  return (
    <div className="flex flex-1 items-center px-16">
      <div className="w-full max-w-[26rem]">
        <Logo size={40} />
        <h1 className="mt-5 text-[28px] font-bold leading-tight">
          Sign in to Azure
        </h1>
        <p className="mt-2 text-base text-fg-muted">
          EZ AzFW Manager reads your Azure Firewalls and their policies. Rule
          changes stay in a local draft until you commit them.
        </p>

        {busy ? (
          <div className="mt-8 flex items-center gap-4">
            <Spinner
              label={
                busy === 'window'
                  ? 'Finish signing in in the sign-in window…'
                  : busy === 'browser'
                    ? 'Finish signing in in your browser…'
                    : 'Checking your Azure CLI sign-in…'
              }
            />
            <button
              className="btn-ghost"
              onClick={() =>
                window.api
                  .cancelSignIn()
                  .catch((err) => setError(errorMessage(err)))
              }
            >
              Cancel
            </button>
          </div>
        ) : (
          <div className="mt-8 flex flex-col gap-2">
            <button
              className="btn-primary h-10 justify-center text-base"
              onClick={() => signIn('window')}
            >
              Sign in with a Microsoft account
            </button>
            <button
              className="btn-outline h-10 justify-center text-base"
              onClick={() => signIn('cli')}
            >
              Use my Azure CLI sign-in
            </button>
            <button
              className="btn-ghost h-9 justify-center text-sm"
              onClick={() => signIn('browser')}
            >
              Sign in with my default browser instead
            </button>
          </div>
        )}

        {error && (
          <div className="mt-5 border-l-2 border-deny bg-deny/10 px-3 py-2 text-sm">
            <p className="font-semibold">Sign-in didn't complete.</p>
            <p className="mt-0.5 whitespace-pre-line text-fg-muted">{error}</p>
          </div>
        )}

        <button
          className="mt-6 flex items-center gap-1 text-sm text-fg-muted hover:text-fg"
          onClick={() => setShowTenant((s) => !s)}
          aria-expanded={showTenant}
        >
          <ChevronRight
            size={14}
            className={`transition-transform ${showTenant ? 'rotate-90' : ''}`}
          />
          Sign in to a specific tenant
        </button>
        {showTenant && (
          <div className="mt-2">
            <label className="label" htmlFor="tenant">
              Tenant domain or ID
            </label>
            <input
              id="tenant"
              className="input"
              placeholder="contoso.onmicrosoft.com"
              value={tenant}
              onChange={(e) => setTenant(e.target.value)}
            />
          </div>
        )}

        <p className="mt-10 text-xs text-fg-faint">
          Access tokens stay in the app's background process and are never shown
          in the interface. You stay signed in on this device (stored encrypted)
          until you sign out.
        </p>
      </div>
    </div>
  );
}
