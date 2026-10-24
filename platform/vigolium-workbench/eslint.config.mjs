// TypeScript is installed side by side, per the TS 7.0 release notes
// ("Running side-by-side with TypeScript 6.0"):
//
//   "typescript": "npm:@typescript/typescript6@…"  — the TS 6 API under the
//     `typescript` name, because typescript-eslint (pulled in by
//     eslint-config-next) throws "typescript-eslint does not support TS 7.0" on
//     load and takes the whole lint run down. See typescript-eslint#10940.
//   "@typescript/native": "npm:typescript@^7…"     — TS 7, which owns `tsc`.
//
// Drop the alias and depend on plain `typescript@^7` once typescript-eslint's
// peer range admits 7 (it is `>=4.8.4 <6.1.0` as of 8.72.0).
//
// ESLint 10 works because eslint-config-next (>=16.4) wraps its bundled plugins
// in its own fixupPluginRules, which restores the context.getFilename() and
// similar methods ESLint 10 removed. eslint-plugin-react 7.37.5 still calls
// them and still caps its peer range at ^9.7, so `bun install` may warn about
// that peer range. The lint run itself is fine.
import { defineConfig, globalIgnores } from 'eslint/config';
import nextVitals from 'eslint-config-next/core-web-vitals';
import nextTs from 'eslint-config-next/typescript';

const eslintConfig = defineConfig([
  ...nextVitals,
  ...nextTs,

  {
    rules: {
      // `next/image` optimizes at request time through the Next server. This app
      // is a static export embedded in a Go binary with `images.unoptimized`, so
      // <Image> would add markup and no optimization. <img> is the right call.
      '@next/next/no-img-element': 'off',

      // Every `window.location.href` here is a deliberate hard navigation, not a
      // router call someone forgot: switching project resets all React Query
      // caches by reloading, the unauthorized "Try again" button re-runs the auth
      // gate from scratch, and api/hooks.ts assigns from inside a queryFn where
      // no router exists. Routing these through next/router would silently
      // preserve the state each one exists to discard.
      '@next/next/no-location-assign-relative-destination': 'off',
    },
  },

  {
    // eslint-plugin-react-hooks 7 turned on the React Compiler rule set. It is
    // worth seeing, but it is new and imprecise on this codebase — `refs` alone
    // fires 380 times, ~344 of them in the two AgentsPage variants where it
    // reads an event handler off a custom hook's return object and reports
    // "Cannot access ref value during render" because that object also carries
    // refs. Demoted to warnings so lint stays a usable gate; `rules-of-hooks`
    // stays an error below, since that one catches real runtime bugs.
    rules: {
      'react-hooks/refs': 'warn',
      'react-hooks/set-state-in-effect': 'warn',
      'react-hooks/immutability': 'warn',
      'react-hooks/preserve-manual-memoization': 'warn',
      'react-hooks/exhaustive-deps': 'warn',
    },
  },

  {
    // Playwright fixtures destructure a callback named `use` (`async ({}, use) =>
    // await use(value)`). That is not React's `use` hook, but the rule matches on
    // the name and reports every fixture as a hooks violation.
    files: ['e2e/**'],
    rules: { 'react-hooks/rules-of-hooks': 'off' },
  },

  // eslint-config-next defaults assume the stock `.next`/`out` layout; this app
  // sets `distDir: 'dist'` (and the e2e run uses `.next-e2e`), so those build
  // outputs have to be listed explicitly or ESLint lints the bundled output.
  globalIgnores([
    '.next/**',
    '.next-e2e/**',
    'dist/**',
    'out/**',
    'build/**',
    'playwright-report/**',
    'test-results/**',
    'next-env.d.ts',
  ]),
]);

export default eslintConfig;
