import { defineConfig } from 'vitest/config';

export default defineConfig({
  esbuild: {
    target: 'es2020'
  },
  test: {
    globals: true,
    environment: 'node',
    coverage: {
      provider: 'v8',
      reporter: ['text', 'json', 'html'],
      exclude: ['node_modules/', 'dist/', '**/*.test.ts']
    }
  }
});
