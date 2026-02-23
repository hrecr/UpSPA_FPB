import type { BgResponse } from '../shared/messages';

async function bg(msg: any): Promise<BgResponse> {
  return (await chrome.runtime.sendMessage(msg)) as BgResponse;
}

async function main() {
  const siteEl = document.getElementById('site')!;
  const statusEl = document.getElementById('status')!;
  const errEl = document.getElementById('error')!;
  const btn = document.getElementById('openOptions')! as HTMLButtonElement;

  btn.onclick = () => chrome.runtime.openOptionsPage();

  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  const origin = tab?.url ? new URL(tab.url).origin : '(no active tab)';
  siteEl.textContent = `Site: ${origin}`;

  const res = await bg({ type: 'UPSRA_GET_CONFIG' });
  if (!res.ok) {
    errEl.textContent = res.error;
    return;
  }

  const cfg = (res as any).cfg as { enabled: boolean; uid: string; threshold: number; sps: any[] };
  if (!cfg?.uid) {
    statusEl.innerHTML = `<div><b>Not configured.</b></div><div class="small">Open Options and run Setup.</div>`;
    return;
  }

  statusEl.innerHTML = `
    <div><b>${cfg.enabled ? 'Enabled' : 'Disabled'}</b></div>
    <div class="small">uid: <code>${cfg.uid}</code></div>
    <div class="small">SPs: ${cfg.sps?.length ?? 0}, threshold: ${cfg.threshold}</div>
    <div class="small">Tip: type your master password into site forms; the extension replaces it with vInfo automatically.</div>
  `;
}

main().catch((e) => {
  const errEl = document.getElementById('error');
  if (errEl) errEl.textContent = String(e);
});
