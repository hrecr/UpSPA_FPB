import type { ManifestV3Export } from '@crxjs/vite-plugin';

export default {
  manifest_version: 3,
  name: 'UpSPA (Project Skeleton)',
  version: '0.1.0',
  description: 'UpSPA browser extension skeleton: mediates between user, Storage Providers, and Login Servers.',

  permissions: ['storage', 'activeTab', 'scripting'],
  host_permissions: ['<all_urls>'],

  background: {
    service_worker: "src/background.ts",
    type: "module",
  },

  content_scripts: [
    {
      matches: ['<all_urls>'],
      js: ['src/content/index.ts'],
      run_at: 'document_idle',
    },
  ],

  action: {
    default_popup: 'src/popup/popup.html',
  },

  options_page: 'src/options/options.html',
} satisfies ManifestV3Export;
