import assert from "node:assert/strict";
import { test } from "node:test";
import { createFeedbackSubmitter, createSubmissionId } from "./feedback-client.mjs";

test("submission IDs are independent version 4 UUIDs", () => {
  const first = createSubmissionId();
  assert.match(first, /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
  assert.notEqual(first, createSubmissionId());
});

test("a lost response retains the same submission ID when retrying", async () => {
  const requests = [];
  const submit = createFeedbackSubmitter(async (url, options) => {
    requests.push({ url, ...options });
    if (requests.length === 1) throw new Error("Response lost after save");
    return { id: 1 };
  }, () => "unique-id");
  const payload = { rating: 5, topic: "general", comment: "Helpful" };
  await assert.rejects(submit(payload), /Response lost/);
  assert.deepEqual(await submit({ ...payload }), { id: 1 });
  assert.deepEqual(requests[0], requests[1]);
  assert.equal(requests[1].headers["Idempotency-Key"], "unique-id");
});

test("changed drafts and new submissions after success get fresh IDs", async () => {
  let nextId = 0;
  const ids = [];
  const submit = createFeedbackSubmitter(async (_url, options) => {
    ids.push(options.headers["Idempotency-Key"]);
    if (ids.length === 1) throw new Error("offline");
    return { id: ids.length };
  }, () => String(++nextId));
  await assert.rejects(submit({ rating: 1 }), /offline/);
  await submit({ rating: 4 });
  await submit({ rating: 4 });
  assert.deepEqual(ids, ["1", "2", "3"]);
});
