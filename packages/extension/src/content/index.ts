import type { BgRequest, BgResponse } from '../shared/messages';

function debug(...args: unknown[]) {
  // Toggle to true for verbose logs
  const enabled = false;
  if (enabled) console.log('[UpSPA]', ...args);
}

async function bg<T extends BgResponse>(msg: BgRequest): Promise<T> {
  const res = (await chrome.runtime.sendMessage(msg)) as T;
  return res;
}

function passwordInputs(form: HTMLFormElement): HTMLInputElement[] {
  const inputs = Array.from(form.querySelectorAll('input')) as HTMLInputElement[];
  return inputs.filter((i) => (i.type || '').toLowerCase() === 'password');
}

function classifyForm(pws: HTMLInputElement[]): 'login' | 'register' | 'change-password' {
  if (pws.length <= 1) return 'login';
  if (pws.length === 2) return 'register';
  return 'change-password';
}

function markProcessed(form: HTMLFormElement): void {
  (form as any).__upspaProcessed = true;
}

function alreadyProcessed(form: HTMLFormElement): boolean {
  return Boolean((form as any).__upspaProcessed);
}

async function handleFormSubmit(form: HTMLFormElement, ev: SubmitEvent): Promise<void> {
  const pws = passwordInputs(form);
  if (pws.length === 0) return;
  if (alreadyProcessed(form)) return;

  const mode = classifyForm(pws);
  const lsj = window.location.origin;

  // User provides master password by typing it into the first password field.
  const masterPassword = pws[0].value;
  if (!masterPassword) return; // let the site handle empty

  // Basic sanity for registration forms
  if (mode === 'register' && pws[1].value !== masterPassword) {
    // If user typed two different things, do not override.
    debug('register form: password fields mismatch; skipping UpSPA transform');
    return;
  }

  ev.preventDefault();

  try {
    if (mode === 'login') {
      const res = await bg<BgResponse>({ type: 'UPSRA_AUTH', lsj, password: masterPassword });
      if (!res.ok) throw new Error(res.error);
      const v = (res as any).vinfo_prime_b64 as string;
      pws[0].value = v;
      markProcessed(form);
      form.submit();
      return;
    }

    if (mode === 'register') {
      const res = await bg<BgResponse>({ type: 'UPSRA_REGISTER', lsj, password: masterPassword });
      if (!res.ok) throw new Error(res.error);
      const v = (res as any).vinfo_b64 as string;
      for (const pw of pws) pw.value = v;
      markProcessed(form);
      form.submit();
      return;
    }

    // change-password / Π4 secret update
    // Heuristic: user types master password in the first (old password) field.
    const prep = await bg<BgResponse>({ type: 'UPSRA_SECRET_UPDATE_PREP', lsj, password: masterPassword });
    if (!prep.ok) throw new Error(prep.error);

    const su = (prep as any).secret_update as {
      vinfo_prime_b64: string;
      vinfo_new_b64: string;
      cj_new: any;
      suids: Array<{ sp_id: number; suid: string }>;
    };

    // Fill old/new/confirm with computed vInfos.
    pws[0].value = su.vinfo_prime_b64;
    if (pws.length >= 2) pws[1].value = su.vinfo_new_b64;
    if (pws.length >= 3) pws[2].value = su.vinfo_new_b64;
    // If more password fields exist, fill them too.
    for (let i = 3; i < pws.length; i++) pws[i].value = su.vinfo_new_b64;

    markProcessed(form);
    form.submit();

    // Best-effort commit: update SP records shortly after the form submission.
    // In a production extension, you would detect success before committing.
    setTimeout(() => {
      bg<BgResponse>({ type: 'UPSRA_SECRET_UPDATE_COMMIT', suids: su.suids, cj_new: su.cj_new })
        .then((r) => {
          if (!r.ok) console.warn('[UpSPA] secret update commit failed:', r.error);
        })
        .catch((e) => console.warn('[UpSPA] secret update commit failed:', e));
    }, 2000);
  } catch (e) {
    console.warn('[UpSPA] failed to transform password:', e);
    // Fall back: let original submission proceed unchanged.
    // But we already prevented default; resubmit without modifying.
    markProcessed(form);
    form.submit();
  }
}

function attachToForms(root: Document | ShadowRoot) {
  const forms = Array.from(root.querySelectorAll('form')) as HTMLFormElement[];
  for (const f of forms) {
    if ((f as any).__upspaBound) continue;
    (f as any).__upspaBound = true;
    f.addEventListener('submit', (ev) => {
      // Fire-and-forget; handler prevents default if it takes over
      void handleFormSubmit(f, ev as SubmitEvent);
    });
  }
}

// Initial attach
attachToForms(document);

// Watch for dynamic SPA pages
const mo = new MutationObserver(() => attachToForms(document));
mo.observe(document.documentElement, { subtree: true, childList: true });
