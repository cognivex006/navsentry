# NavSentry Recorder (Chrome / Edge extension)

Record a user journey on a site you are authorized to test, with a screenshot of each step, and turn it into a NavSentry draft flow. The agent then works from your clicks and screenshots instead of guessing.

The recorder only observes what you do in your own browser. It has no network access of its own, never records what you type, and never photographs a password field. NavSentry's own safety checks (scope gate, budget) apply when the flow is replayed.

## Install (unpacked)

1. Download or check out NavSentry; this folder is `extension/`.
2. Open `chrome://extensions` (Chrome) or `edge://extensions` (Edge).
3. Turn on **Developer mode** and choose **Load unpacked**.
4. Select the `extension/` folder.

It is not published in the Chrome Web Store or Edge Add-ons (owner decision D7).

## Set the scope

1. Open the extension's options (**Details → Extension options**, or **Scope settings** in the popup).
2. Choose your project's `navsentry.json`. Only `targets.origins` is read, and only when `authorization.acknowledged` is true.

The first time you press **Record** on an origin, the browser asks you to grant the recorder access to that one origin. It never asks for all sites. **Remove the imported scope** on the same page clears the scope and gives back any access you granted.

## Record

1. Open a page of the application and open the popup. Check what it shows before you start:
   - **Scope badge:** *in scope ✓*, *not in scope* (with the origins that are) or *no scope*. **● Record** is enabled only on an in-scope page.
   - **What this recorder never does:** it never stores what you type, takes no screenshot right after typing or on a password field, has no network access, and records only the tab you started, on origins in your imported scope. A later screenshot can still show text that stays on the page, so record with test data.
   Then press **● Record**.
2. Use the site normally. Each click, field change and form submit becomes a step with a screenshot.
   - Typed values are not stored; only that a field was filled is recorded. There is no screenshot right after typing or on a password field, but a later step's screenshot can show text that stays on the page. Record with test data.
   - Only the tab you started is photographed. If a click opens another tab or leaves the scope, that step has no screenshot.
   - If you leave the scope, the recorder writes "left the scope" without the address and pauses until you come back.
3. Press **■ Stop**.
4. Review the steps in the popup:
   - **Delete** steps you do not want.
   - Tick **flow ends here** on the last step that matters.
   - Add a note for the reviewer, for example "order list is shown".
5. Press **⬇ Save file**. The browser's download dialog saves `navsentry-<host>-<date>.navrec.zip`. Once the download completes, the popup shows the exact `navsentry flow from-recording` command for the file you saved, with a **Copy command** button. The saved path is kept only in the extension's local storage, to show that command, and is removed by Clear.

Buttons are enabled only when they can act: Stop while recording, Save and Clear after stopping. Clear asks before it deletes the recording.

## Turn it into a flow

```bash
navsentry flow from-recording --input navsentry-<host>-<date>.navrec.zip --out navsentry/flows/drafts
```

This writes three things:

- `<id>.flow.md`: the draft flow.
- `<id>.RECORDING.md`: each step with its screenshot and your note.
- `<id>.shots/`: the screenshots, with a `.gitignore` so they are not committed.

Screenshots may show personal data, so delete them once the flow is approved. Set the listed environment variables for the filled fields, review the draft, and approve it as the owner. Then replay it:

```bash
navsentry scan --mode flow --flows navsentry/flows/drafts --engine playwright
```

## What it does not do

- It sends no requests and has no `fetch`, sockets or remote code. Its CSP blocks connections.
- It does not read field values, cookies or storage of the page.
- It does not run on pages outside the origins you imported.
