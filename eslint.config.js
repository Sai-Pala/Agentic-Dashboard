/**
 * Lint configuration.
 *
 * Tuned to catch BUGS, not to enforce taste. Every rule enabled below can fail a build, so each
 * one has to earn that by catching something that would otherwise reach the browser or the
 * server — a typo'd identifier, a variable left behind by a refactor, a `case` that falls
 * through. Formatting opinions (quotes, semicolons, line length) are deliberately absent: this
 * codebase is already internally consistent, and a formatter fight adds churn without catching
 * a single defect.
 *
 * Three module systems live here and they are NOT interchangeable:
 *   server.js, src/, test/   CommonJS on Node
 *   public/js/               native ES modules in the browser, no bundler
 *   sast-engine/             vendored ESM — excluded, see below
 */

const js = require('@eslint/js');

/** Rules worth failing on, beyond eslint:recommended. */
const BUG_RULES = {
  // A name that survived a refactor is the single most common dead-code smell here, and the
  // `_`-prefix escape hatch keeps deliberate signature padding legal.
  'no-unused-vars': ['error', {
    args: 'after-used',
    argsIgnorePattern: '^_',
    varsIgnorePattern: '^_',
    caughtErrors: 'none',
  }],
  // Shadowing is how a fix gets applied to the wrong variable and still passes review.
  'no-shadow': 'error',
  'no-var': 'error',
  'prefer-const': ['error', { destructuring: 'all' }],
  eqeqeq: ['error', 'smart'],
  'no-implicit-coercion': 'off',
  'no-return-await': 'error',
  // An await inside a loop is usually intended here (sequential agent stages), so it is a hint
  // rather than a failure.
  'no-await-in-loop': 'off',
  'no-promise-executor-return': 'error',
  'require-atomic-updates': 'off',
  'no-constant-binary-expression': 'error',
  'no-self-compare': 'error',
  'no-template-curly-in-string': 'warn',
  'no-unmodified-loop-condition': 'error',
  'no-unreachable-loop': 'error',
  'default-case-last': 'error',
  'no-fallthrough': 'error',
};

module.exports = [
  {
    // Vendored from `ship-safe` (MIT). Linting it would produce a standing list of findings
    // nobody may act on — the rule files are treated with extreme caution and are not ours to
    // restyle. Excluded so `npm run lint` stays at zero and therefore stays meaningful.
    // test/fixtures/ is deliberately-vulnerable sample code the golden tests scan. Its unused
    // middleware and dead branches ARE the fixture — linting them would demand "fixes" that
    // change what the engine is measured against.
    ignores: ['node_modules/**', 'sast-engine/**', 'coverage/**', 'test/fixtures/**'],
  },

  // ── CommonJS on Node: the server, its modules, and the tests ──────────────
  {
    files: ['server.js', 'src/**/*.js', 'test/**/*.js', 'eslint.config.js'],
    languageOptions: {
      ecmaVersion: 2023,
      sourceType: 'commonjs',
      globals: {
        require: 'readonly',
        module: 'writable',
        exports: 'writable',
        process: 'readonly',
        __dirname: 'readonly',
        __filename: 'readonly',
        console: 'readonly',
        Buffer: 'readonly',
        setTimeout: 'readonly',
        clearTimeout: 'readonly',
        setInterval: 'readonly',
        clearInterval: 'readonly',
        setImmediate: 'readonly',
        URL: 'readonly',
        fetch: 'readonly',
        AbortSignal: 'readonly',
        WebSocket: 'readonly',
        structuredClone: 'readonly',
      },
    },
    rules: { ...js.configs.recommended.rules, ...BUG_RULES },
  },

  // ── Native ES modules in the browser. No bundler: extensions are load-bearing ──
  {
    files: ['public/js/**/*.js'],
    languageOptions: {
      ecmaVersion: 2023,
      sourceType: 'module',
      globals: {
        window: 'readonly',
        document: 'readonly',
        console: 'readonly',
        location: 'readonly',
        localStorage: 'readonly',
        navigator: 'readonly',
        fetch: 'readonly',
        crypto: 'readonly',
        WebSocket: 'readonly',
        alert: 'readonly',
        confirm: 'readonly',
        setTimeout: 'readonly',
        clearTimeout: 'readonly',
        setInterval: 'readonly',
        clearInterval: 'readonly',
        requestAnimationFrame: 'readonly',
        Event: 'readonly',
        KeyboardEvent: 'readonly',
        CustomEvent: 'readonly',
        URLSearchParams: 'readonly',
        HTMLElement: 'readonly',
        getComputedStyle: 'readonly',
      },
    },
    rules: { ...js.configs.recommended.rules, ...BUG_RULES },
  },
];
