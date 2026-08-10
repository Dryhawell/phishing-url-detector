/**
 * Popup kontrolcüsü:
 * - Hızlı Analiz: istemci heuristikleri
 * - Derin Analiz: yerel Python API (http://127.0.0.1:8765)
 */

const API_BASE = "http://127.0.0.1:8765";

const urlInput = document.getElementById("urlInput");
const analyzeBtn = document.getElementById("analyzeBtn");
const deepBtn = document.getElementById("deepBtn");
const scoreLine = document.getElementById("scoreLine");
const levelLine = document.getElementById("levelLine");
const problemsList = document.getElementById("problemsList");
const note = document.getElementById("note");

/**
 * @param {{ score: number, level: string, problems: string[], invalid?: boolean }} result
 * @param {string} [sourceLabel]
 */
function renderResult(result, sourceLabel) {
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

  if (sourceLabel && note) {
    note.textContent = sourceLabel;
  }
}

function runQuickAnalysis() {
  const raw = (urlInput.value || "").trim();
  if (!raw) {
    renderResult(
      {
        score: 0,
        level: "SAFE",
        problems: ["Lütfen bir URL girin."],
        invalid: true,
      },
      "URL gerekli."
    );
    return;
  }
  const result = self.PhishingHeuristics.analyzeUrl(raw);
  renderResult(
    {
      score: result.score,
      level: result.level,
      problems: result.problems,
      invalid: result.invalid,
    },
    "Kaynak: istemci tarafı hızlı heuristik (Python API kullanılmadı)."
  );
}

async function runDeepAnalysis() {
  const raw = (urlInput.value || "").trim();
  if (!raw) {
    renderResult(
      {
        score: 0,
        level: "SAFE",
        problems: ["Lütfen bir URL girin."],
        invalid: true,
      },
      "URL gerekli."
    );
    return;
  }

  deepBtn.disabled = true;
  analyzeBtn.disabled = true;
  note.textContent = "Python API'ye bağlanılıyor... (python main.py --api)";

  try {
    const response = await fetch(`${API_BASE}/analyze`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: raw }),
    });

    if (!response.ok) {
      const errBody = await response.json().catch(() => ({}));
      throw new Error(errBody.error || `HTTP ${response.status}`);
    }

    const data = await response.json();
    renderResult(
      {
        score: data.risk_score ?? 0,
        level: data.is_valid === false ? "INVALID" : data.risk_level || "SAFE",
        problems:
          data.is_valid === false
            ? [data.error || "Geçersiz URL"]
            : data.problems || [],
        invalid: data.is_valid === false,
      },
      "Kaynak: yerel Python API (WHOIS / HTML / blocklist dahil olabilir)."
    );
  } catch (error) {
    renderResult(
      {
        score: 0,
        level: "SAFE",
        problems: [
          "Python API'ye ulaşılamadı.",
          "Önce terminalde çalıştırın: python main.py --api",
          String(error && error.message ? error.message : error),
        ],
        invalid: true,
      },
      "Derin analiz için yerel API ayakta olmalı (127.0.0.1:8765)."
    );
  } finally {
    deepBtn.disabled = false;
    analyzeBtn.disabled = false;
  }
}

analyzeBtn.addEventListener("click", runQuickAnalysis);
deepBtn.addEventListener("click", () => {
  runDeepAnalysis();
});
urlInput.addEventListener("keydown", (event) => {
  if (event.key === "Enter") runQuickAnalysis();
});

chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
  const tab = tabs && tabs[0];
  if (
    tab &&
    tab.url &&
    !tab.url.startsWith("chrome://") &&
    !tab.url.startsWith("edge://")
  ) {
    urlInput.value = tab.url;
    runQuickAnalysis();
  }
});
