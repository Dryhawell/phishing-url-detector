/**
 * İstemci tarafı sezgisel (heuristic) kurallar.
 * Python detector/heuristics.py ile aynı fikir; tarayıcıda hafif tutularak
 * anlık kontrol sağlar (WHOIS/HTML/blocklist yok).
 */

const RISK_SCORES = {
  noHttps: 20,
  ipInUrl: 30,
  longDomain: 10,
  longUrl: 10,
  manySubdomains: 15,
  atSymbol: 25,
  doubleSlash: 20,
  hyphenInDomain: 10,
  tooManyDigits: 15,
  suspiciousTld: 25,
  phishingKeyword: 15,
};

const SUSPICIOUS_TLDS = new Set([
  "xyz",
  "top",
  "click",
  "ru",
  "tk",
  "gq",
  "ml",
  "cf",
]);

const PHISHING_KEYWORDS = [
  "login",
  "verify",
  "secure",
  "account",
  "update",
  "bank",
  "paypal",
  "crypto",
];

const MAX_DOMAIN_LENGTH = 25;
const MAX_URL_LENGTH = 75;
const MAX_SUBDOMAIN_COUNT = 2;
const MAX_DIGIT_COUNT = 5;

/**
 * @param {number} score
 * @returns {"SAFE"|"SUSPICIOUS"|"HIGH_RISK"}
 */
function getRiskLevel(score) {
  const clamped = Math.max(0, Math.min(score, 100));
  if (clamped <= 20) return "SAFE";
  if (clamped <= 50) return "SUSPICIOUS";
  return "HIGH_RISK";
}

/**
 * @param {string} hostname
 * @returns {boolean}
 */
function isIpAddress(hostname) {
  if (!hostname) return false;
  // Basit IPv4 kontrolü (eğitim eklentisi için yeterli).
  return /^(?:\d{1,3}\.){3}\d{1,3}$/.test(hostname);
}

/**
 * @param {string} hostname
 * @returns {{ domain: string, subdomainParts: string[], tld: string }}
 */
function splitHost(hostname) {
  const host = (hostname || "").toLowerCase().replace(/\.$/, "");
  const parts = host.split(".").filter(Boolean);
  if (parts.length === 0) {
    return { domain: "", subdomainParts: [], tld: "" };
  }
  if (parts.length === 1) {
    return { domain: parts[0], subdomainParts: [], tld: "" };
  }
  const tld = parts[parts.length - 1];
  const domain = parts[parts.length - 2];
  const subdomainParts = parts.slice(0, -2);
  return { domain, subdomainParts, tld };
}

/**
 * Aktif sekme URL'sini analiz et.
 * @param {string} rawUrl
 * @returns {{ url: string, score: number, level: string, problems: string[] }}
 */
function analyzeUrl(rawUrl) {
  /** @type {string[]} */
  const problems = [];
  let score = 0;

  let url;
  try {
    url = new URL(rawUrl);
  } catch {
    return {
      url: rawUrl,
      score: 0,
      level: "SAFE",
      problems: ["URL parse edilemedi."],
      invalid: true,
    };
  }

  if (url.protocol !== "https:") {
    score += RISK_SCORES.noHttps;
    problems.push("HTTPS kullanılmıyor");
  }

  const host = url.hostname;
  if (isIpAddress(host)) {
    score += RISK_SCORES.ipInUrl;
    problems.push(`IP adresi kullanılmış (${host})`);
  }

  const { domain, subdomainParts, tld } = splitHost(host);
  if (domain && domain.length > MAX_DOMAIN_LENGTH) {
    score += RISK_SCORES.longDomain;
    problems.push(`Domain çok uzun (${domain.length} karakter)`);
  }

  if (rawUrl.length > MAX_URL_LENGTH) {
    score += RISK_SCORES.longUrl;
    problems.push(`URL çok uzun (${rawUrl.length} karakter)`);
  }

  if (subdomainParts.length > MAX_SUBDOMAIN_COUNT) {
    score += RISK_SCORES.manySubdomains;
    problems.push(`Çok fazla alt domain (${subdomainParts.length} adet)`);
  }

  // userinfo@host tuzağı: https://apple.com:pass@evil.com
  if (url.username || rawUrl.includes("@")) {
    // URL API username varsa kesin; aksi halde @ path/query'de de olabilir.
    if (url.username || url.href.includes("@")) {
      score += RISK_SCORES.atSymbol;
      problems.push("URL içerisinde @ karakteri var");
    }
  }

  if (url.pathname.includes("//")) {
    score += RISK_SCORES.doubleSlash;
    problems.push("URL içerisinde // yönlendirmesi var");
  }

  if (domain.includes("-")) {
    score += RISK_SCORES.hyphenInDomain;
    problems.push("Domain içinde '-' kullanımı var");
  }

  const digits = (rawUrl.match(/\d/g) || []).length;
  if (digits >= MAX_DIGIT_COUNT) {
    score += RISK_SCORES.tooManyDigits;
    problems.push(`URL içinde çok fazla rakam var (${digits} adet)`);
  }

  if (SUSPICIOUS_TLDS.has(tld)) {
    score += RISK_SCORES.suspiciousTld;
    problems.push(`Şüpheli uzantı (.${tld})`);
  }

  const lowered = rawUrl.toLowerCase();
  for (const word of PHISHING_KEYWORDS) {
    if (lowered.includes(word)) {
      score += RISK_SCORES.phishingKeyword;
      problems.push(`Şüpheli kelime bulundu: '${word}'`);
    }
  }

  const clamped = Math.max(0, Math.min(score, 100));
  return {
    url: url.href,
    score: clamped,
    level: getRiskLevel(clamped),
    problems,
    invalid: false,
  };
}

// Service worker / popup paylaşımı için export benzeri global.
self.PhishingHeuristics = { analyzeUrl, getRiskLevel };
