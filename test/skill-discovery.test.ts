import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, existsSync } from "node:fs";
import { dirname, resolve } from "node:path";

test("Codex entrypoint resolves the canonical skill and integration guide", () => {
  const entry = resolve(".agents/skills/navsentry/SKILL.md");
  const text = readFileSync(entry, "utf8");
  const links = [...text.matchAll(/`(\.\.\/[^`]+\.md)`/g)].map(m => resolve(dirname(entry), m[1]!));
  assert.ok(links.includes(resolve("skills/navsentry/SKILL.md")));
  assert.ok(links.includes(resolve("docs/AGENT-INTEGRATIONS.md")));
  for (const link of links) assert.ok(existsSync(link), `missing entrypoint resource: ${link}`);
  for (const file of [entry, resolve("skills/navsentry/SKILL.md")]) {
    assert.match(readFileSync(file, "utf8"), /^---\r?\nname: navsentry\r?\ndescription: .+\r?\n---/);
  }
});
