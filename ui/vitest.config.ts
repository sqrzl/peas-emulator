import { defineConfig } from 'vite-plus';
import { askr } from '@askrjs/vite';

export default defineConfig({
  plugins: [askr()],
  test: {
    environment: 'jsdom',
    globals: true,
    coverage: {
      reporter: ['text', 'json', 'html'],
    },
  },
});
