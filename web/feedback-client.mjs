// Retain an ID after uncertain failures so retrying cannot inflate statistics.
// State lives only in memory; a changed draft starts a new submission.
export function createSubmissionId() {
  // getRandomValues also works on HTTP trusted-network previews.
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  bytes[6] = (bytes[6] & 15) | 64;
  bytes[8] = (bytes[8] & 63) | 128;
  const hex = Array.from(bytes, (value) => value.toString(16).padStart(2, "0")).join("");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

export function createFeedbackSubmitter(send, createId = createSubmissionId) {
  let pending = null;
  return async (payload) => {
    const body = JSON.stringify(payload);
    if (!pending || pending.body !== body) pending = { body, id: createId() };
    const result = await send("/api/feedback", {
      method: "POST",
      headers: { "Content-Type": "application/json", "Idempotency-Key": pending.id },
      body,
    });
    pending = null;
    return result;
  };
}
