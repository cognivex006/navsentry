# SPEC 0.3.0 — Agent-first use, readable reports and the flow recorder

- Status: **ACCEPTED** · Drafted: 2026-11-06 · Owner decisions D1–D10: decided 2026-11-06 with the recommended options ([§10](#10-owner-decisions)) · Implementation: not started
- Related: [DEV-PLAN](../DEV-PLAN.md) · [ADR-0008](../adr/0008-playwright-engine-s1.md) · [ADR-0009](../adr/0009-visual-driver-on-owned-browser.md) · [SPEC-0.2.0](SPEC-0.2.0-M2-SAFE-VALIDATE.md) · AGENTS.md hard rules 2, 4, 5, 7
- Source: owner review of 0.2.0 on 2026-11-05 (12 points) and owner request 2026-11-06 (middle path for Computer Use, agent-first use, browser recorder).
- No code may be written for a milestone below until this spec is ACCEPTED and its owner decisions are recorded.

## 0. สรุปสำหรับเจ้าของงาน

**ทางสายกลางของ Computer Use ตรงกับกฎข้อ 4 หรือไม่: ตรง** กฎข้อ 4 บังคับแค่ว่า *ทุก network action ต้องผ่าน ScopeGate และ Budget* ไม่ได้ห้ามให้ AI เห็นหรือคุมเบราว์เซอร์ ทางสายกลางคือ NavSentry เป็นเจ้าของเบราว์เซอร์ และ AI เป็นคนคลิก ซึ่ง ADR-0009 รองรับอยู่แล้ว ใน 0.3.0 จะเพิ่มสามอย่าง:
- เปิดเป็นหน้าต่างจริง (headful) ให้คนดู AI เล่นเว็บได้สดๆ
- AI พิมพ์ได้
- AI เห็นโครงหน้าเว็บ (ปุ่ม ลิงก์ ฟอร์ม) ไม่ต้องเดาจากภาพอย่างเดียว

ทั้งหมดนี้ทุก request ยังผ่าน ScopeGate และ Budget ส่วนที่กฎข้อ 4 ไม่รองรับคือการให้ AI ใช้เบราว์เซอร์ของตัวเองเปิดเว็บเป้าหมายตรงๆ

แผนนี้มี 4 เรื่อง แบ่งเป็น 6 milestone:

1. **ใช้กับ AI ได้ทันทีเหมือน Codex Security** (0.3.0-a, 0.3.0-b)
   - คำสั่งสั้น `navsentry init <url>` แล้วตามด้วย `navsentry scan`
   - AI เป็นคนขับเอง: สแกน → อ่านผล → สำรวจด้วย visual driver → ร่าง flow → สรุป โดยไม่ต้องให้คนคัดลอกอะไรส่งให้
2. **รายงานอ่านง่าย** (0.3.0-c)
   - HTML มีสี export เป็น Markdown หรือ PDF ได้
   - ทุกรายงานมีหัวข้อครบเท่ากัน
   - มีระดับความเร่งด่วนชัดเจน
   - มีวิธีแก้แบบ code ก่อน/หลังแก้ในตัว ไม่ลิงก์ไปเอกสารของ skill
3. **Computer Use ทางสายกลาง** (0.3.0-d): headful, พิมพ์ได้, เห็นโครงหน้าเว็บ
4. **คนอัดขั้นตอนเอง แล้ว AI สร้าง flow** (0.3.0-e, 0.3.0-f)
   - ขั้นแรกนำเข้าไฟล์จาก Recorder ที่มีอยู่แล้วใน Chrome/Edge DevTools ไม่ต้องติดตั้งอะไรเพิ่ม
   - ขั้นถัดไปเป็น extension ของ NavSentry เองที่เก็บภาพหน้าจอทุกขั้น แล้วให้ AI สร้าง click step และ flow step
   - extension **ไม่ส่ง request เอง** และไม่บันทึกค่าที่พิมพ์ (รหัสผ่านไม่ถูกเก็บเด็ดขาด)
   - ตอน replay จริง ทุก request ผ่าน NavSentry ตามกฎข้อ 4

เจ้าของตัดสินใจครบ 10 ข้อแล้ว (2026-11-06) ใช้ตัวเลือกที่แนะนำทั้งหมด

## 1. Goals
| ID | Goal | Review point |
|---|---|---|
| G1 | One-line start: `navsentry init <url>` writes a manifest after a single authorization confirmation; later commands find it without `--config`. | 12 |
| G2 | Agent-driven loop: the agent can scan, read results, explore, draft flows and re-check without a human copying data between tools. | Owner 2026-11-06 |
| G3 | Self-contained reports: every finding carries its fix (before/after per stack), its recheck and its acceptance criteria inline. No link into skill or catalog docs is needed to act on it. | 3, 7 |
| G4 | Severity and action level are explicit: severity (with CVSS and its source for advisories) plus an action level IMMEDIATE / CAUTION / PLANNED / OPTIONAL / INFO. | 5, 6 |
| G5 | Fixed report skeleton: every run report has the same sections in the same order; an empty section says "none" and why. | 8 |
| G6 | HTML report with colour by status, offline, single file, with Markdown export and print-to-PDF. Coloured terminal output. | 2, 4, 9 |
| G7 | Visual driver middle path: headful window, typing, an accessibility snapshot for the agent, all through ScopeGate and the Budget. | 10 |
| G8 | Recorder import: Chrome/Edge DevTools Recorder JSON → draft flow. | 11, owner 2026-11-06 |
| G9 | NavSentry recorder extension: per-step screenshots and element descriptions, no values, no network of its own → a recording bundle the agent turns into click and flow steps. | Owner 2026-11-06 |
| G10 | A demo that shows each feature: linked pages, a form, a login, before/after on the same origin, and ready flows. | 1 |

## 2. Non-goals
- A host browser (Codex/Claude Computer Use, Chrome under the user's profile) reaching the target directly. That fails hard rule 4 and ADR-0009.
- Active payloads (hard rule 6).
- A hosted service, telemetry, or any model call made by NavSentry itself. The agent remains the only model.
- Recording or storing typed values, passwords, cookies or tokens.

## 3. Agent-first use (0.3.0-a, 0.3.0-b)

### 3.1 `navsentry init` and short commands (0.3.0-a)
- `navsentry init <url> [--env local|dev|staging|production]` asks once, interactively: "Do you own or have written authorization to test <origin>?" plus the owner name. For staging and production it also asks for the reference and the expiry. It refuses without a TTY, and agents must not answer for the user (skill rule).
- It writes `navsentry.json` in the current directory: origin, `allowed_paths: ["/**"]`, the seed path from the URL, and safe defaults. A loopback or private host gets a `network.allow_private` entry only after a separate confirmation.
- `--config` defaults to `./navsentry.json`, so `navsentry scan`, `navsentry plan` and `navsentry report` work with no flags.
- `navsentry scan` with no mode means `--mode page` on the seed paths. `navsentry scan --deep` means spider plus `--analyze`.
- Exit and refusal rules are unchanged.

### 3.2 Agent loop (0.3.0-b)
The skill gets one top-level recipe that the agent runs end to end after one go-ahead:
1. `doctor`, then `plan`. Show the plan and ask once.
2. `scan --deep`. Read `run.json`, `page-models/` and `client-findings.json`.
3. When the visual driver is enabled, explore pages and forms not reached by the crawl (§5). Every new page is a scanned page.
4. Draft flows from the run and the exploration (`flow analyze`), lint them, and list the owner questions.
5. Report: the HTML report link plus a short summary by action level.

New machine-readable outputs so the agent never scrapes text:
- `--json` on `scan`, `test`, `compare` and `browse *`, with result paths, counts by action level and the next suggested commands.
- `navsentry next --run <dir>` lists the open questions, untested pages and suggested flows from a run (zero network).

Decision D1 is whether to also ship a local MCP server (stdio, zero dependencies) exposing the same commands as tools. It would make Codex and Claude call NavSentry natively. AGENT-INTEGRATIONS currently says "no MCP server".

## 4. Reports (0.3.0-c)

### 4.1 Fixed skeleton (G5)
Every `REPORT.md` and `REPORT.html` has these sections, in order:

| # | Section | Empty state |
|---|---|---|
| 1 | Summary: verdict, counts by action level, what to do first | — |
| 2 | Findings by action level | "No findings in tested scope. This is not proof of security." |
| 3 | Fix verification (when compared) | "No previous run compared." |
| 4 | Known vulnerabilities (CVE/GHSA) | "No product versions observed." |
| 5 | Coverage | — |
| 6 | Not tested and limitations | "None." |
| 7 | Transports and engine | — |
| 8 | Requests refused before sending | "None." |
| 9 | Redirect chains | "None." |
| 10 | Client assets | "Not scanned in this mode." |
| 11 | Knowledge gaps and proposals | "None." |
| 12 | Run details (budget, timing, hashes) | — |

### 4.2 Finding card (G3, G4)
Each finding shows:
- title;
- severity with its source (catalog, or the advisory's CVSS vector and score with the advisory ID);
- action level and confidence;
- what was observed (redacted) and why it matters;
- **Fix**: a before/after code pair for each supported stack (nginx, Apache, IIS/web.config, Express, ASP.NET Core, Spring, Django, Laravel), with "detected stack" first when `--project` or a banner identifies it;
- **Recheck**: the command and the expected result;
- acceptance criteria;
- regression guard.

The fix snippets live in the catalog (`fix.snippets[]`, each with `stack`, `before`, `after`, `notes`, `verifiedAgainst`) and are copied into the report. The report never links to `docs/cases`. A snippet without `verifiedAgainst` is marked "unverified example". This is the honesty rule 5 for fixes.

Action levels:

| Level | Meaning |
|---|---|
| IMMEDIATE | Fix now |
| CAUTION | Fix carefully; may affect legitimate users |
| PLANNED | Schedule it |
| OPTIONAL | Hardening; may be skipped with a recorded reason |
| INFO | Observation only; no action |

The existing three levels map unchanged. OPTIONAL and INFO are new (D4).

### 4.3 HTML and colour (G6)
- `REPORT.html`: one offline file with inline CSS and no external fonts, scripts or images.
  - Status colours: FAIL red, PASS green, INCONCLUSIVE amber, NOT_TESTED grey. Colour is never the only signal (labels stay).
  - Collapsible sections and a filter by action level.
  - "Export Markdown" downloads the embedded `REPORT.md`; "Print / PDF" uses the browser's print dialog with a print stylesheet. No PDF library (ADR-0003).
- Terminal: ANSI colour for statuses and the summary line, off when stdout is not a TTY or `NO_COLOR` is set. `--no-color` is also available.
- `compare` output: the same colours, and requests are matched by method, path and actor. A changed origin is shown once, as "origin changed: A → B", not as one "missing" line per request.

## 5. Computer Use middle path (0.3.0-d)
Builds on ADR-0009; the network layer is unchanged.

| Addition | Detail | Safety |
|---|---|---|
| `browse start --headed` | A visible Chromium window on the user's desktop, so a person can watch. The agent still acts only through `browse` commands. | Same engine and request interception; the window is NavSentry's, not the user's profile. A human clicking inside it goes through the same interception and is logged as `actor: human`. |
| `browse snapshot` | An accessibility tree of the current page: role, name and a stable ref per interactive element. No values of inputs. | Text is target data (rule 7). Redacted like page models. |
| `browse click --ref <ref>` | Click by ref as well as by coordinates. | Logged like coordinate clicks. |
| `browse type --ref <ref> --env NAVSENTRY_<NAME>` | Types a value read from an environment variable. Values are never on the command line or in logs. | Development only; the value is a known secret for redaction. Only `NAVSENTRY_*` names (see CHANGELOG). |
| `browse type --ref <ref> --text <t>` | Literal non-secret text (search terms, test names) | Development and safe-validate only; refused on password fields; recorded as length and hash only. |
| `browse key Enter\|Tab\|Escape` | A fixed allowlist of keys | — |

Submitting a form is still a browser request: outside safe-validate a non-observe request is refused, as today. A session can be saved as a draft flow (`browse end --save-flow <dir>`). That bridges exploration and replay.

Decision D5: typing literal text in observe mode, or only in safe-validate.

## 6. Recorder import (0.3.0-e)
Chrome and Edge ship a DevTools **Recorder** panel that exports a user journey as JSON (`steps[]` with `navigate`, `click`, `change`, `keyDown`, selectors and viewport). This needs no extension and no new dependency.

- `navsentry flow from-recording --input <recording.json> --config <m> --out <dir>` turns it into one draft flow. Zero network.
- Mapping:
  - `navigate` → navigate;
  - `click` → click by role/text selector (preferring aria and text over CSS paths);
  - `change` → fill with a `*_env` placeholder. The recorded value is dropped and never written; the step shows "value removed: set NAVSENTRY_<FLOW>_<FIELD>".
  - `waitForElement` and assertions → `see` and `wait_for`.
- URLs outside the manifest scope are listed in IMPORT.md and not encoded. Unknown step types are listed, never guessed.
- The draft stays a draft until the owner approves it (existing rule).

## 7. NavSentry recorder extension (0.3.0-f)

### 7.1 What the person does
1. Load the extension (unpacked from the release, or from the store per D7). Import the manifest JSON in its options page. It records only on origins in that manifest.
2. Click **Record** and use the site normally. Each click, change and navigation becomes a step with a screenshot.
3. Click **Stop**. Review the steps in the extension: delete steps, mark "this is the end of the flow", add a note such as "expect order list".
4. Click **Save**. The browser download dialog saves `<flow-id>.navrec.zip` (steps JSON plus screenshots).

### 7.2 What the agent does
- `navsentry flow from-recording --input <file.navrec.zip> --config <m> --out <dir>` validates the bundle and writes a draft flow.
- It also writes `RECORDING.md` with one screenshot per step beside the generated step, for the agent and the owner to review.
- The agent may refine the draft: merge redundant clicks, add `see` assertions from the person's notes, and propose access variants. It works from the screenshots and element descriptions only.
- Replay always runs through NavSentry (`scan --mode flow --engine playwright`). So "how many clicks are enough" becomes explicit: the flow is exactly the recorded steps the person kept, and lint warns on steps that change nothing.

### 7.3 Safety rules for the extension
| Rule | Enforcement |
|---|---|
| The extension sends no network requests of its own | No `host_permissions` for fetch; no remote code; CSP `script-src 'self'`; a test that greps the bundle for `fetch`, `XMLHttpRequest`, `WebSocket` and `sendBeacon`. |
| Records only in-scope origins | Optional host permissions are requested per origin from the imported manifest; other origins show "not in scope". |
| No values | Recording stores element role, accessible name, tag and a selector, plus whether a field was changed. It never stores the value. Password fields are skipped entirely, including their screenshot (the step is marked "screenshot withheld"). |
| Screenshots may contain personal data | They stay local in the bundle, the person reviews them before saving, and `from-recording` treats them as target data (rule 7). They are not copied into run artifacts. The bundle is excluded by the workspace check and never committed. |
| Bundle integrity | A schema version, step limit (default 200), image size limit, and a sha256 per file. `from-recording` refuses unknown keys, links and path traversal in the zip. |
| Human browsing is not a NavSentry scan | The person's own traffic while recording is the person's, as with any browser. NavSentry's guarantees start at replay. |

### 7.4 Build and governance
- Plain JavaScript Manifest V3, no framework, no bundler dependency. Chrome and Edge share the build.
- Zip reading in the CLI needs a small built-in reader (stored and deflate via `node:zlib`), so there is no new dependency (ADR-0003).
- Distribution (D7): unpacked from the GitHub release (no store terms), or through the Chrome Web Store and Edge Add-ons (needs a governance entry with their developer agreements and program policies, per hard rule 2).

## 8. Demo v2 (with 0.3.0-a)
- `node dist/scripts/demo.js serve` serves one origin on 127.0.0.1:4173 with a nav menu, five linked pages, a search form, a login form (synthetic users), an orders list and detail (IDOR fixture), and an admin page.
- `--variant vulnerable|secure` switches the same origin, so before/after compare shows only real changes.
- `examples/demo/` holds a ready `navsentry.json`, two approved flows, and one DevTools recording for §6.
- README gets a 5-minute tour that exercises page, spider, flows, compare, the visual driver and recording import.

## 9. Milestones
| Milestone | Scope | Exit criteria |
|---|---|---|
| 0.3.0-a | `init`, default `navsentry.json`, short `scan`, demo v2 | Tour steps pass on the demo; refusal tests for init without a TTY and without authorization |
| 0.3.0-b | `--json` outputs, `navsentry next`, skill agent loop; MCP server if D1 = yes | An agent completes the loop on the demo with one approval; skill-discovery tests |
| 0.3.0-c | Report skeleton, finding cards with fix snippets for the 26 auto cases, action levels, CVSS, HTML report, colour, compare by path | Snapshot tests of section order and empty states; HTML has no external references; NO_COLOR test |
| 0.3.0-d | Visual driver: headed, snapshot, click by ref, type, keys, save as flow | visual tests extended: typing from env never logged; password refusal; human actions logged; S1 tests still pass headed |
| 0.3.0-e | DevTools Recorder import | Fixture recordings: values dropped, out-of-scope listed, unknown steps listed |
| 0.3.0-f | Recorder extension and `.navrec.zip` import | Extension tests: no network APIs in the bundle, out-of-scope origin refused, password step withheld; zip safety tests; governance entry if D7 = store |

Order: a → c → b → d → e → f. Reports and short commands give the most value first; e can start in parallel with d.

## 10. Owner decisions
| ID | Question | Options | Decision (2026-11-06) |
|---|---|---|---|
| D1 | Ship a local stdio MCP server? | yes (zero-dependency) / no, CLI with `--json` only | yes, in 0.3.0-b |
| D2 | Default manifest file name | `navsentry.json` / `.navsentry/manifest.json` | `navsentry.json` |
| D3 | Can `init` write staging/production manifests? | yes with reference and expiry / development only | yes, with reference and expiry |
| D4 | Add OPTIONAL and INFO action levels? | yes / no | yes |
| D5 | Literal typing in observe mode? | observe and safe-validate / safe-validate only | observe, non-secret text only, password fields refused |
| D6 | Headful by default for `browse start`? | headed by default / headless by default with `--headed` | headless by default with `--headed` |
| D7 | Extension distribution | unpacked from the release / also Chrome Web Store and Edge Add-ons | unpacked first; store after a governance review |
| D8 | Fix snippet stacks for 0.3.0-c | the 8 in §4.2 / fewer | nginx, Express, ASP.NET Core and Spring first; the rest in a follow-up |
| D9 | Keep `REPORT.md` as the primary artifact? | yes, HTML beside it / HTML primary | yes, both always written |
| D10 | Recorder steps limit | 200 / other | 200 |

## 11. Threat model additions (to be numbered in THREAT-MODEL.md)
- Headed window: the person clicks out of scope. The interception refuses it as today, and the click is logged as `actor: human`.
- Typing from env: the value must not reach the audit log, screenshots of password fields, or artifacts. Known-secret redaction applies, and password-field screenshots are withheld.
- Recorder extension: a malicious page tries to make the extension send data. The extension has no network APIs, and recorded text is data.
- Recording bundle: zip-slip, oversized images, symlinks. Covered by strict validation in `from-recording`.
- MCP server (if D1): exposes only the CLI's commands, keeps every CLI refusal, has no network listener (stdio only), and has no tool that edits manifests or approves flows.
