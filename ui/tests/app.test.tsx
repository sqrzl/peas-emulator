import { describe, expect, it } from 'vite-plus/test';

describe('SPA template structure', () => {
  it('documents the route-first shell boundaries the app should keep', () => {
    const structure = [
      'src/main.tsx',
      'src/pages/_routes.tsx',
      'src/pages/_layout.tsx',
      'src/pages/app/_routes.tsx',
      'src/pages/app/_layout.tsx',
      'src/pages/app/admin-home.tsx',
      'src/pages/app/agent-runs.tsx',
      'src/features/operations/operations.query.ts',
      'src/adapters/index.ts',
      'src/adapters/storage-overview-client.ts',
      'src/components/shared/metric-card.tsx',
    ];

    expect(structure).toContain('src/pages/_routes.tsx');
    expect(structure).toContain('src/pages/app/_layout.tsx');
    expect(structure).toContain('src/features/operations/operations.query.ts');
    expect(structure).toContain('src/adapters/storage-overview-client.ts');
  });
});
