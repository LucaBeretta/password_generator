import { createFeedbackSubmitter } from "./feedback-client.mjs";

const form = document.querySelector("#feedback-form");

if (form) {
  const submitButton = document.querySelector("#feedback-submit");
  const refreshButton = document.querySelector("#feedback-refresh");
  const status = document.querySelector("#feedback-status");
  const statsStatus = document.querySelector("#feedback-stats-status");
  const average = document.querySelector("#feedback-average");
  const count = document.querySelector("#feedback-count");
  const distribution = document.querySelector("#rating-distribution");
  let submitting = false;
  let refreshing = false;
  let refreshPending = false;
  let feedbackUnavailable = false;
  const feedbackPanel = form.closest(".feedback-panel");

  function setStatus(element, message, kind = "") {
    element.textContent = message;
    element.dataset.kind = kind;
  }

  async function request(url, options = {}) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 15000);
    try {
      const response = await fetch(url, { ...options, signal: controller.signal });
      if (!response.ok) {
        const error = new Error("The feedback server could not complete the request.");
        error.status = response.status;
        throw error;
      }
      return await response.json();
    } finally {
      clearTimeout(timeout);
    }
  }

  const submitFeedback = createFeedbackSubmitter(request);

  function renderStats(stats) {
    if (!Number.isInteger(stats.count) || stats.count < 0 ||
        (stats.count > 0 && (!Number.isFinite(stats.average_rating) || stats.average_rating < 1 || stats.average_rating > 5)) ||
        !stats.ratings || [1, 2, 3, 4, 5].some((rating) => !Number.isInteger(stats.ratings[rating]) || stats.ratings[rating] < 0) ||
        [1, 2, 3, 4, 5].reduce((sum, rating) => sum + stats.ratings[rating], 0) !== stats.count) {
      throw new Error("Invalid statistics response.");
    }
    average.textContent = stats.count ? stats.average_rating.toFixed(1) : "—";
    count.textContent = stats.count ? `${stats.count.toLocaleString()} ${stats.count === 1 ? "response" : "responses"} submitted` : "No feedback yet. Be the first to share yours.";
    distribution.replaceChildren();
    for (const rating of [5, 4, 3, 2, 1]) {
      const total = stats.ratings[rating];
      const row = document.createElement("div");
      row.className = "rating-row";
      const label = document.createElement("span");
      label.textContent = `${rating} / 5`;
      const bar = document.createElement("progress");
      bar.max = stats.count || 1;
      bar.value = total;
      bar.setAttribute("aria-label", `${rating} out of 5: ${total} responses`);
      const value = document.createElement("span");
      value.className = "rating-total";
      value.textContent = total.toLocaleString();
      row.append(label, bar, value);
      distribution.append(row);
    }
  }

  async function refreshStats() {
    if (refreshing) {
      refreshPending = true;
      return;
    }
    refreshing = true;
    refreshButton.disabled = true;
    setStatus(statsStatus, "Loading community feedback…");
    try {
      renderStats(await request("/api/feedback/stats", { cache: "no-store" }));
      feedbackUnavailable = false;
      form.hidden = false;
      feedbackPanel.removeAttribute("data-unavailable");
      setStatus(statsStatus, "");
    } catch (error) {
      if ([404, 405, 501].includes(error.status)) {
        feedbackUnavailable = true;
        form.hidden = true;
        feedbackPanel.setAttribute("data-unavailable", "true");
        average.textContent = "—";
        count.textContent = "Feedback is unavailable on this version.";
        distribution.replaceChildren();
        setStatus(statsStatus, "This page has no shared feedback service. Password generation and encryption still work locally.");
      } else {
        if (count.textContent === "Loading feedback…") count.textContent = "Statistics unavailable";
        setStatus(statsStatus, "Could not refresh statistics. Try Refresh when the server is available.", "error");
      }
    } finally {
      refreshing = false;
      refreshButton.disabled = false;
      if (refreshPending) {
        refreshPending = false;
        await refreshStats();
      }
    }
  }

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (submitting || feedbackUnavailable || !form.reportValidity()) return;
    submitting = true;
    submitButton.disabled = true;
    submitButton.textContent = "Sending…";
    form.setAttribute("aria-busy", "true");
    setStatus(status, "Sending your feedback…");
    const data = new FormData(form);
    const payload = {
      rating: Number(data.get("rating")),
      topic: data.get("topic"),
      comment: String(data.get("comment") || "").trim(),
    };
    try {
      await submitFeedback(payload);
      form.reset();
      setStatus(status, "Thank you. Your feedback has been saved.", "success");
      await refreshStats();
    } catch {
      setStatus(status, "Could not confirm your submission. Your draft is still here. Retry without changing it to avoid a duplicate.", "error");
    } finally {
      submitting = false;
      submitButton.disabled = false;
      submitButton.textContent = "Send feedback";
      form.removeAttribute("aria-busy");
    }
  });

  refreshButton.addEventListener("click", refreshStats);
  refreshStats();
}
