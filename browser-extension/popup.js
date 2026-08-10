/**
 * Popup kontrolcüsü: aktif sekme URL'sini al, heuristik çalıştır, UI güncelle.
 */

const urlInput = document.getElementById("urlInput");
const analyzeBtn = document.getElementById("analyzeBtn");
const scoreLine = document.getElementById("scoreLine");
const levelLine = document.getElementById("levelLine");
const problemsList = document.getElementById("problemsList");

/**
 * @param {{ score: number, level: string, problems: string[], invalid?: boolean }} result
 */
function renderResult(result) {
  if (result.invalid) {
    scoreLine.textContent = "Risk Skoru: —";
    levelLine.textContent = "Durum: INVALID";
    levelLine.className = "level INVALID";
  } else {
    scoreLine.textContent = `Risk Skoru: ${result.score}`;
    levelLine.textContent = `Durum: ${result.level}`;
    levelLine.className = `level ${result.level}`;
  }

  problemsList.innerHTML = "";
  const items =
    result.problems && result.problems.length
      ? result.problems
      : ["Belirgin bir problem bulunamadı."];

  for (const item of items) {
    const li = document.createElement("li");
    li.textContent = item;
    problemsList.appendChild(li);
  }
}

function runAnalysis() {
  const raw = (urlInput.value || "").trim();
  if (!raw) {
    renderResult({
      score: 0,
      level: "SAFE",
      problems: ["Lütfen bir URL girin."],
      invalid: true,
    });
    return;
  }
  const result = self.PhishingHeuristics.analyzeUrl(raw);
  renderResult(result);
}

analyzeBtn.addEventListener("click", runAnalysis);
urlInput.addEventListener("keydown", (event) => {
  if (event.key === "Enter") runAnalysis();
});

// Açılışta aktif sekme URL'sini doldur.
chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
  const tab = tabs && tabs[0];
  if (tab && tab.url && !tab.url.startsWith("chrome://") && !tab.url.startsWith("edge://")) {
    urlInput.value = tab.url;
    runAnalysis();
  }
});
