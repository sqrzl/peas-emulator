import { describe, expect, it } from 'vite-plus/test';

describe('SPA template structure', () => {
  it('documents the route-first shell boundaries the app should keep', () => {
    const structure = [
      'src/main.tsx',
      'src/pages/_routes.tsx',
      'src/pages/_layout.tsx',
      'src/pages/public/_routes.tsx',
      'src/pages/public/_layout.tsx',
      'src/pages/app/_routes.tsx',
      'src/pages/app/_layout.tsx',
      'src/features/operations/operations.query.ts',
      'src/adapters/operations-client.ts',
      'src/components/shared/metric-card.tsx',
    ];

    expect(structure).toContain('src/pages/_routes.tsx');
    expect(structure).toContain('src/pages/app/_layout.tsx');
    expect(structure).toContain('src/features/operations/operations.query.ts');
    expect(structure).toContain('src/adapters/operations-client.ts');
  });
});
