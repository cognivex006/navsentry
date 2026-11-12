/** SPEC-0.4.0 §5: ASVS 5.0 requirement IDs stay consistent with the pinned source and the catalog. */
import { test } from "node:test";
import assert from "node:assert/strict";
import { CASES } from "../src/catalog.js";
import { ASVS5_IDS, ASVS5_NO_REQUIREMENT, ASVS5_REQUIREMENTS, ASVS5_SOURCE } from "../src/asvs5.js";

test("every mapped ID exists in ASVS 5.0.0 and belongs to a chapter the case already maps", () => {
  assert.equal(ASVS5_IDS.size, 297);
  const byId = new Map(CASES.map((c) => [c.id, c]));
  for (const [id, reqs] of Object.entries(ASVS5_REQUIREMENTS)) {
    const c = byId.get(id);
    assert.ok(c, `${id} is a catalog case`);
    assert.equal(new Set(reqs).size, reqs.length, `${id} has no duplicate IDs`);
    const chapters = new Set(c!.asvs5Chapter.map((ch) => ch.split(" ")[0]!.slice(1)));
    for (const r of reqs) {
      assert.ok(ASVS5_IDS.has(r), `${id}: ${r} is in ASVS 5.0.0`);
      assert.ok(chapters.has(r.split(".")[0]!), `${id}: ${r} is in a chapter the catalog maps (${[...chapters].join(",")})`);
    }
  }
});

test("an empty mapping always says why, and every case with an ASVS chapter is mapped", () => {
  for (const [id, reqs] of Object.entries(ASVS5_REQUIREMENTS)) if (!reqs.length) assert.ok(ASVS5_NO_REQUIREMENT[id], `${id} explains its empty mapping`);
  for (const id of Object.keys(ASVS5_NO_REQUIREMENT)) assert.deepEqual(ASVS5_REQUIREMENTS[id], [], `${id} has a reason only when it maps nothing`);
  for (const c of CASES) if (c.asvs5Chapter.length) assert.ok(c.id in ASVS5_REQUIREMENTS, `${c.id} has a requirement-level entry`);
});

test("the source is pinned and the review status is not claimed", () => {
  assert.match(ASVS5_SOURCE.commit, /^[0-9a-f]{40}$/);
  assert.equal(ASVS5_SOURCE.status, "pending-independent-review", "only an independent reviewer may flip this");
});
