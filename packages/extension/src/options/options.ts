import type { BgResponse } from '../shared/messages';
import type { ExtensionConfig } from '../shared/config';

async function bg(msg: any): Promise<BgResponse> {
  return (await chrome.runtime.sendMessage(msg)) as BgResponse;
}

function setMsg(text: string, kind: 'ok' | 'err' | 'info' = 'info') {
  const el = document.getElementById('msg')!;
  el.className = `small ${kind === 'ok' ? 'ok' : kind === 'err' ? 'err' : ''}`;
  el.textContent = text;
}

function parseConfigFromUi(): ExtensionConfig {
  const enabled = (document.getElementById('enabled') as HTMLInputElement).checked;
  const uid = (document.getElementById('uid') as HTMLInputElement).value.trim();
  const threshold = Number((document.getElementById('threshold') as HTMLInputElement).value);

  const rows = Array.from(document.querySelectorAll('.sp-row')) as HTMLElement[];
  const sps = rows
    .map((r) => {
      const id = Number((r.querySelector('input[data-role="id"]') as HTMLInputElement).value);
      const baseUrl = (r.querySelector('input[data-role="url"]') as HTMLInputElement).value.trim();
      return { id, baseUrl };
    })
    .filter((sp) => sp.id && sp.baseUrl);

  return { enabled, uid, threshold, sps };
}

function renderSpList(sps: Array<{ id: number; baseUrl: string }>) {
  const host = document.getElementById('spList')!;
  host.innerHTML = '';

  for (const sp of sps) {
    const row = document.createElement('div');
    row.className = 'sp-row';
    row.innerHTML = `
      <input data-role="id" type="number" min="1" step="1" value="${sp.id}" placeholder="id" />
      <input data-role="url" value="${sp.baseUrl}" placeholder="https://sp.example.com" />
      <button type="button" data-role="rm">Remove</button>
    `;
    (row.querySelector('[data-role="rm"]') as HTMLButtonElement).onclick = async () => {
      row.remove();
      await saveConfig();
    };
    // autosave on change
    for (const inp of Array.from(row.querySelectorAll('input'))) {
      (inp as HTMLInputElement).addEventListener('change', () => void saveConfig());
    }

    host.appendChild(row);
  }
}

async function saveConfig(): Promise<void> {
  const cfg = parseConfigFromUi();
  const res = await bg({ type: 'UPSRA_SET_CONFIG', cfg });
  if (!res.ok) {
    setMsg(res.error, 'err');
  } else {
    setMsg('Saved.', 'ok');
  }
}

async function loadConfigToUi() {
  const res = await bg({ type: 'UPSRA_GET_CONFIG' });
  if (!res.ok) {
    setMsg(res.error, 'err');
    return;
  }
  const cfg = (res as any).cfg as ExtensionConfig;
  (document.getElementById('enabled') as HTMLInputElement).checked = cfg.enabled;
  (document.getElementById('uid') as HTMLInputElement).value = cfg.uid;
  (document.getElementById('threshold') as HTMLInputElement).value = String(cfg.threshold);
  renderSpList(cfg.sps ?? []);
}

async function runSetup() {
  const pwd = (document.getElementById('setupPassword') as HTMLInputElement).value;
  if (!pwd) {
    setMsg('Master password required for Setup.', 'err');
    return;
  }
  const cfg = parseConfigFromUi();
  if (!cfg.uid) {
    setMsg('UID is required.', 'err');
    return;
  }
  if (!cfg.sps.length) {
    setMsg('At least one SP is required.', 'err');
    return;
  }
  if (!(cfg.threshold >= 1 && cfg.threshold <= cfg.sps.length)) {
    setMsg('Threshold must be between 1 and number of SPs.', 'err');
    return;
  }

  setMsg('Running Setup…');
  const res = await bg({
    type: 'UPSRA_SETUP_AND_PROVISION',
    uid: cfg.uid,
    password: pwd,
    threshold: cfg.threshold,
    sps: cfg.sps,
  });

  if (!res.ok) {
    setMsg(`Setup failed: ${res.error}`, 'err');
    return;
  }
  setMsg('Setup successful and SPs provisioned.', 'ok');
}

async function runPasswordUpdate() {
  const oldPwd = (document.getElementById('oldPwd') as HTMLInputElement).value;
  const newPwd = (document.getElementById('newPwd') as HTMLInputElement).value;
  if (!oldPwd || !newPwd) {
    setMsg('Old and new passwords are required.', 'err');
    return;
  }
  const ts = Math.floor(Date.now() / 1000);
  setMsg('Running password update…');
  const res = await bg({ type: 'UPSRA_PASSWORD_UPDATE', old_password: oldPwd, new_password: newPwd, timestamp: ts });
  if (!res.ok) {
    setMsg(`Password update failed: ${res.error}`, 'err');
    return;
  }
  setMsg('Password update applied (at least threshold SPs).', 'ok');
}

async function main() {
  await loadConfigToUi();

  (document.getElementById('enabled') as HTMLInputElement).addEventListener('change', () => void saveConfig());
  (document.getElementById('uid') as HTMLInputElement).addEventListener('change', () => void saveConfig());
  (document.getElementById('threshold') as HTMLInputElement).addEventListener('change', () => void saveConfig());

  (document.getElementById('addSp') as HTMLButtonElement).onclick = async () => {
    const cfg = parseConfigFromUi();
    const nextId = (cfg.sps.map((s) => s.id).reduce((a, b) => Math.max(a, b), 0) || 0) + 1;
    cfg.sps.push({ id: nextId, baseUrl: '' });
    renderSpList(cfg.sps);
    await saveConfig();
  };

  (document.getElementById('runSetup') as HTMLButtonElement).onclick = () => void runSetup();
  (document.getElementById('runPwdUpdate') as HTMLButtonElement).onclick = () => void runPasswordUpdate();
}

main().catch((e) => setMsg(String(e), 'err'));
