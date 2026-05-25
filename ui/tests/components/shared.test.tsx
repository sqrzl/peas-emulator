import { describe, expect, it } from 'vite-plus/test';
import MetricCard from '../../src/components/shared/metric-card';

describe('shared app components', () => {
  it('exports small app-local wrappers around theme primitives', () => {
    expect(MetricCard).toBeDefined();
    expect(typeof MetricCard).toBe('function');
  });
});
