# Publishing to npm

## Prerequisites

1. **npm account**: Register at https://www.npmjs.com/signup
2. **Node.js 18+** installed

## Step 1: Verify the Package Name is Available

```cmd
npm view mcp-security-auditor
```

If it returns 404, the name is available.

## Step 2: Login to npm

```cmd
npm login
```

Enter your npm username, password, and email. If you have 2FA enabled, enter your OTP.

## Step 3: Build

```cmd
cd mcp-security-auditor-npm
npm install
npm run build
```

## Step 4: Test Locally

```cmd
node dist\cli.js scan .\test-fixtures\vulnerable-server
node dist\cli.js --version
node dist\cli.js analyzers
```

## Step 5: Dry Run (Preview What Gets Published)

```cmd
npm pack --dry-run
```

This shows you exactly which files will be in the package. Verify it includes:
- `dist/**` (compiled JS)
- `README.md`
- `LICENSE`
- `package.json`

## Step 6: Publish

```cmd
npm publish --access public
```

If you have 2FA enabled, you'll be prompted for an OTP.

## Step 7: Verify

```cmd
:: Test npx (zero-install usage)
npx mcp-security-auditor --version
npx mcp-security-auditor scan .\test-fixtures\vulnerable-server

:: Test global install
npm install -g mcp-security-auditor
mcp-audit --version
mcp-audit scan .\test-fixtures\vulnerable-server
```

## Updating the Package

1. Update version in `package.json` (e.g., 1.0.0 → 1.0.1)
2. Also update VERSION in `src/core/models.ts`
3. Rebuild: `npm run build`
4. Publish: `npm publish`

## Automated Publishing via GitHub Actions

The `.github/workflows/publish.yml` is already set up. To use it:

1. Push code to GitHub
2. Go to npm → Access Tokens → Generate New Token (Automation)
3. In GitHub repo → Settings → Secrets → Add `NPM_TOKEN`
4. Create a GitHub Release → package auto-publishes

## npm Badge for README

After publishing, add this to your GitHub README:

```markdown
[![npm version](https://img.shields.io/npm/v/mcp-security-auditor.svg)](https://www.npmjs.com/package/mcp-security-auditor)
[![npm downloads](https://img.shields.io/npm/dm/mcp-security-auditor.svg)](https://www.npmjs.com/package/mcp-security-auditor)
```
