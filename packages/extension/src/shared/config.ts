export interface ExtensionConfig {
  enabled: boolean;
  uid: string;
  threshold: number;
  sps: Array<{ id: number; baseUrl: string }>;
}

export const DEFAULT_CONFIG: ExtensionConfig = {
  enabled: true,
  uid: '',
  threshold: 3,
  sps: [
    { id: 1, baseUrl: 'https://sp1.example.com' },
    { id: 2, baseUrl: 'https://sp2.example.com' },
    { id: 3, baseUrl: 'https://sp3.example.com' },
  ],
};

const STORAGE_KEY = 'upspa.config';

export async function getConfig(): Promise<ExtensionConfig> {
  const v = await chrome.storage.local.get(STORAGE_KEY);
  return (v[STORAGE_KEY] as ExtensionConfig) ?? DEFAULT_CONFIG;
}

export async function setConfig(cfg: ExtensionConfig): Promise<void> {
  await chrome.storage.local.set({ [STORAGE_KEY]: cfg });
}
