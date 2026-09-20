// Two dependency ceilings are load-bearing here and are not free to bump:
//
//   typescript pinned to 6.x — typescript-eslint refuses to load against TS 7
//     ("typescript-eslint does not support TS 7.0"), and eslint-config-next
//     requires it, so TS 7 takes the whole lint run down, not just the TS rules.
//     See typescript-eslint#10940.
//   eslint pinned to 9.x — eslint-config-next's peer range is a loose >=9.0.0,
//     but its transitive eslint-plugin-react (7.37.5, latest) caps at ^9.7 and
//     calls context.getFilename(), removed in ESLint 10.
//
// Raising either one re-breaks `bun run lint` outright. Re-check both upstreams
// before bumping. Last re-verified 2026-09-20 against typescript 7.0.2 and
// eslint 10.11.0 (with typescript-eslint 8.70.0): both still fail as described.
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
