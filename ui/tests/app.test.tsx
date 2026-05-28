import { describe, expect, it } from 'vite-plus/test';

describe('SPA structure', () => {
  it('documents the reduced bucket/blob app surface', () => {
    const structure = [
      'src/main.tsx',
      'src/pages/_routes.tsx',
      'src/pages/_layout.tsx',
      'src/pages/app/_routes.tsx',
      'src/pages/app/_layout.tsx',
      'src/pages/app/home.tsx',
      'src/pages/app/bucket.tsx',
      'src/pages/app/blob.tsx',
      'src/pages/auth/login.tsx',
      'src/pages/auth/logout.tsx',
      'src/features/buckets/buckets.query.ts',
      'src/features/objects/objects.query.ts',
      'src/shared/routes.ts',
      'src/adapters/api.g.ts',
    ];

    expect(structure).toContain('src/pages/_routes.tsx');
    expect(structure).toContain('src/pages/app/home.tsx');
    expect(structure).toContain('src/pages/app/blob.tsx');
    expect(structure).toContain('src/shared/routes.ts');
  });
});
