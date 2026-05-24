import { describe, expect, it } from 'vite-plus/test';
import MetricCard from '../../src/components/shared/metric-card';
import StatusBadge from '../../src/components/shared/status-badge';

describe('shared app components', () => {
  it('exports small app-local wrappers around theme primitives', () => {
    expect(MetricCard).toBeDefined();
    expect(StatusBadge).toBeDefined();
    expect(typeof MetricCard).toBe('function');
    expect(typeof StatusBadge).toBe('function');
  });
});
