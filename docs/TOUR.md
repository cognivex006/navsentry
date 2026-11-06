# NavSentry in 10 minutes (demo shop)

This tour runs every mode against the bundled demo shop: a synthetic website on 127.0.0.1 with linked pages, a search form, a sign-in form, orders and an admin API. Nothing leaves your machine.

You need a NavSentry checkout with Node.js 22.12 or newer. For the browser steps you also need the Chromium headless shell; `navsentry doctor` shows `playwright-browser USABLE` when it is installed.

```bash
npm install
```

```bash
npm run build
```

```bash
npx playwright-core install --only-shell chromium
```

The commands below use `navsentry`. From a checkout without a global install, use `node ../../dist/src/cli.js` instead, run from `examples/demo`.

## 1. Start the demo shop

In its own terminal:

```bash
node dist/scripts/demo.js serve
```

Open http://127.0.0.1:4173/ in your browser to see what you are testing. This is the **vulnerable** variant.

## 2. Go to the demo folder

```bash
cd examples/demo
```

It holds `navsentry.json` (the manifest) and `flows/` (two approved story flows). Every command finds `navsentry.json` automatically, so no `--config` is needed.

For your own application, create the manifest with `navsentry init <url>` instead. It asks you to confirm that you are authorized to test the target, then writes `navsentry.json`.

## 3. One page

```bash
navsentry scan --out runs/page
```

Scans the seed page `/`. Open `runs/page/REPORT.md`.

## 4. The whole site (spider)

```bash
navsentry scan --deep --out runs/deep
```

Follows the links (`/products`, `/products/1`, `/search`, `/login`, …), samples a few pages per template, scans client assets, and writes redacted page models in `runs/deep/page-models/`.

## 5. Story flows

The orders flow uses three demo actors. Their tokens are synthetic demo values; set them in the terminal (PowerShell: `$env:NAME = "value"`):

```bash
export NAVSENTRY_DEMO_READER_A_AUTH="Bearer fixture-reader-a-token" NAVSENTRY_DEMO_READER_B_AUTH="Bearer fixture-reader-b-token" NAVSENTRY_DEMO_ADMIN_AUTH="Bearer fixture-admin-token"
```

Run both flows. The shop flow clicks through the site in NavSentry's own browser:

```bash
navsentry scan --mode flow --flows flows --engine playwright --out runs/before
```

Open `runs/before/TEST-REPORT.md`. `shop-browse` passes. `orders-access` fails, because the vulnerable shop lets reader B open reader A's order, lets anonymous visitors read a profile, and lets readers see admin stats.

To write your own flow, start from a template and edit the steps:

```bash
navsentry flow init --id my-journey --title "My journey" --out flows
```

Check it, then approve it as the owner:

```bash
navsentry flow lint --flows flows
```

```bash
navsentry flow approve --flows flows/my-journey.flow.md --by "<your name>"
```

You can also draft flows from a run with `navsentry flow analyze --from-run runs/deep/run.json --out flows/drafts`.

## 6. Fix and compare

Stop the demo shop (Ctrl+C) and start the fixed variant on the same address:

```bash
node dist/scripts/demo.js serve --variant secure
```

Run the same flows again:

```bash
navsentry scan --mode flow --flows flows --engine playwright --out runs/after
```

Compare the two runs:

```bash
navsentry compare --before runs/before --after runs/after
```

The verdict is `IMPROVED_NO_DRIFT`: the access-control findings are fixed, nothing a legitimate user sees has changed, and no story step regressed.

## 7. Computer Use (visual driver)

The AI agent looks at screenshots and clicks, while NavSentry owns the browser and checks every request. Start a session in its own terminal:

```bash
navsentry browse start --url http://127.0.0.1:4173/ --out runs/visual
```

It prints `SESSION: <id>`. In another terminal, or from your agent:

```bash
navsentry browse screenshot --session <id>
```

```bash
navsentry browse click --x 640 --y 400 --session <id>
```

```bash
navsentry browse end --session <id>
```

Read `runs/visual/VISUAL-SESSION.md`. To let an agent do it, ask in Claude Code or Codex: *"Use the navsentry skill to explore http://127.0.0.1:4173/ with the visual driver from examples/demo and summarize what it finds."*

## 8. Clean up

Stop the demo shop, then delete `examples/demo/runs/` (it is ignored by git, but it holds reports of the demo).
