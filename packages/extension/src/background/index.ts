import { UpspaClient } from 'upspa-js';

import { getConfig, setConfig } from '../shared/config';
import type { BgRequest, BgResponse } from '../shared/messages';

async function getClient(): Promise<{ cfg: Awaited<ReturnType<typeof getConfig>>; client: UpspaClient }> {
  const cfg = await getConfig();
  if (!cfg.uid) throw new Error('UpSPA not configured: uid is empty (open extension Options).');
  if (!cfg.sps?.length) throw new Error('UpSPA not configured: no SPs set.');
  if (cfg.threshold < 1 || cfg.threshold > cfg.sps.length) throw new Error('UpSPA config invalid: threshold out of range.');

  const client = new UpspaClient({ uid: cfg.uid, threshold: cfg.threshold, sps: cfg.sps });
  await client.init();
  return { cfg, client };
}

chrome.runtime.onMessage.addListener((msg: BgRequest, _sender, sendResponse) => {
  (async (): Promise<BgResponse> => {
    try {
      switch (msg.type) {
        case 'UPSRA_GET_CONFIG': {
          const cfg = await getConfig();
          return { ok: true, cfg };
        }

        case 'UPSRA_SET_CONFIG': {
          await setConfig(msg.cfg);
          return { ok: true };
        }

        case 'UPSRA_SETUP_AND_PROVISION': {
          const cfg = {
            enabled: true,
            uid: msg.uid,
            threshold: msg.threshold,
            sps: msg.sps,
          };
          await setConfig(cfg);

          const client = new UpspaClient({ uid: cfg.uid, threshold: cfg.threshold, sps: cfg.sps });
          await client.setupAndProvision(msg.password, cfg.threshold);
          return { ok: true };
        }

        case 'UPSRA_REGISTER': {
          const { cfg, client } = await getClient();
          if (!cfg.enabled) throw new Error('UpSPA is disabled in options');
          const out = await client.register(msg.lsj, msg.password);
          return { ok: true, vinfo_b64: out.to_ls.vinfo };
        }

        case 'UPSRA_AUTH': {
          const { cfg, client } = await getClient();
          if (!cfg.enabled) throw new Error('UpSPA is disabled in options');
          const out = await client.authenticate(msg.lsj, msg.password);
          return { ok: true, vinfo_prime_b64: out.vinfo_prime };
        }

        case 'UPSRA_SECRET_UPDATE_PREP': {
          const { cfg, client } = await getClient();
          if (!cfg.enabled) throw new Error('UpSPA is disabled in options');
          const out = await client.secretUpdate(msg.lsj, msg.password);
          return {
            ok: true,
            secret_update: {
              vinfo_prime_b64: out.vinfo_prime,
              vinfo_new_b64: out.vinfo_new,
              cj_new: out.cj_new,
              suids: out.suids,
              old_ctr: out.old_ctr,
              new_ctr: out.new_ctr,
            },
          };
        }

        case 'UPSRA_SECRET_UPDATE_COMMIT': {
          const { cfg, client } = await getClient();
          if (!cfg.enabled) throw new Error('UpSPA is disabled in options');
          await client.applySecretUpdateToSPs(msg.suids, msg.cj_new);
          return { ok: true };
        }

        case 'UPSRA_PASSWORD_UPDATE': {
          const { cfg, client } = await getClient();
          if (!cfg.enabled) throw new Error('UpSPA is disabled in options');
          const out = await client.passwordUpdate(msg.old_password, msg.new_password, msg.timestamp);
          return { ok: true, password_update: { cid_new: out.cid_new } };
        }

        default:
          return { ok: false, error: `Unknown message: ${(msg as any).type}` };
      }
    } catch (e) {
      return { ok: false, error: e instanceof Error ? e.message : String(e) };
    }
  })()
    .then(sendResponse)
    .catch((e) => sendResponse({ ok: false, error: String(e) }));

  // keep message channel open for async
  return true;
});
