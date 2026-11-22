const state = {
  manifest: null,
  entryById: new Map(),
  entryByName: new Map(),
  shardCache: new Map(),
  specialData: null,
  ipv4Data: null,
  ipv6Data: null,
  defaultClient: "singbox",
  themeMode: "system",
  browseAll: false,
  filterKind: "all",
  resultLimit: 36,
  cardSelections: new Map(),
  renderedEntries: new Map(),
  activeEntry: null,
  activeSnippet: "singbox",
  snippetSource: "direct",
  previewRows: [],
  previewLimit: 100,
  querySeq: 0,
};

const el = {
  brandResetBtn: document.getElementById("brandResetBtn"),
  summaryLine: document.getElementById("summaryLine"),
  queryModeTag: document.getElementById("queryModeTag"),
  queryInput: document.getElementById("queryInput"),
  clearQueryBtn: document.getElementById("clearQueryBtn"),
  kbdHint: document.getElementById("kbdHint"),
  suggestionsBar: document.getElementById("suggestionsBar"),
  browseAllBtn: document.getElementById("browseAllBtn"),
  resultsSection: document.getElementById("resultsSection"),
  resultsHeading: document.getElementById("resultsHeading"),
  resultsMeta: document.getElementById("resultsMeta"),
  resultsTools: document.getElementById("resultsTools"),
  resultsGrid: document.getElementById("resultsGrid"),
  resultsFooter: document.getElementById("resultsFooter"),
  loadMoreBtn: document.getElementById("loadMoreBtn"),
  drawerBackdrop: document.getElementById("drawerBackdrop"),
  detailDrawer: document.getElementById("detailDrawer"),
  drawerTitle: document.getElementById("drawerTitle"),
  drawerMeta: document.getElementById("drawerMeta"),
  closeDrawerBtn: document.getElementById("closeDrawerBtn"),
  snippetCode: document.getElementById("snippetCode"),
  copySnippetBtn: document.getElementById("copySnippetBtn"),
  previewKindSelect: document.getElementById("previewKindSelect"),
  previewSearchInput: document.getElementById("previewSearchInput"),
  previewStatus: document.getElementById("previewStatus"),
  previewList: document.getElementById("previewList"),
  previewPager: document.getElementById("previewPager"),
  previewMoreBtn: document.getElementById("previewMoreBtn"),
};

const CHECK_SVG = `<svg viewBox="0 0 14 14" width="11" height="11" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M2.5 7.5 5.5 10.5 11.5 3.5"/></svg>`;
const CHEVRON_SVG = `<svg viewBox="0 0 12 12" width="11" height="11" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M4.5 2.5 8 6l-3.5 3.5"/></svg>`;
const LINK_SVG = `<svg viewBox="0 0 16 16" width="13" height="13" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M6.7 9.3a3.2 3.2 0 0 0 4.5 0l1.6-1.6a3.2 3.2 0 0 0-4.5-4.5L7.4 4.1"/><path d="M9.3 6.7a3.2 3.2 0 0 0-4.5 0L3.2 8.3a3.2 3.2 0 0 0 4.5 4.5l.9-.9"/></svg>`;
const MIRROR_SVG = `<svg viewBox="0 0 16 16" width="13" height="13" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M8.8 2 3.6 9h4.1l-.5 5 5.2-7H8.3l.5-5Z"/></svg>`;

async function copyText(text, triggerBtn = null) {
  try {
    await navigator.clipboard.writeText(text);
  } catch {
    const ta = document.createElement("textarea");
    ta.value = text;
    document.body.appendChild(ta);
    ta.select();
    document.execCommand("copy");
    ta.remove();
  }
  if (triggerBtn) {
    triggerBtn.classList.add("copied");
    const statusEl = triggerBtn.querySelector(".copy-state");
    if (statusEl) {
      statusEl.innerHTML = `${CHECK_SVG}<span>已复制</span>`;
    } else if (triggerBtn.dataset.defaultText) {
      triggerBtn.textContent = "已复制";
    }
    clearTimeout(triggerBtn._copyTimer);
    triggerBtn._copyTimer = setTimeout(() => {
      triggerBtn.classList.remove("copied");
      if (statusEl) {
        statusEl.textContent = "复制";
      } else if (triggerBtn.dataset.defaultText) {
        triggerBtn.textContent = triggerBtn.dataset.defaultText;
      }
    }, 1500);
  }
}

const systemThemeQuery = window.matchMedia ? window.matchMedia("(prefers-color-scheme: dark)") : null;

function resolveTheme(mode) {
  if (mode === "light" || mode === "dark") return mode;
  return systemThemeQuery && systemThemeQuery.matches ? "dark" : "light";
}

function initTheme() {
  const saved = localStorage.getItem("sbr_theme_mode");
  const mode = saved === "light" || saved === "dark" || saved === "system" ? saved : "system";
  applyThemeMode(mode);
  if (systemThemeQuery) {
    systemThemeQuery.addEventListener("change", () => {
      if (state.themeMode === "system") {
        document.documentElement.setAttribute("data-theme", resolveTheme("system"));
      }
    });
  }
}

function applyThemeMode(mode) {
  state.themeMode = mode;
  localStorage.setItem("sbr_theme_mode", mode);
  document.documentElement.setAttribute("data-theme", resolveTheme(mode));
  document.querySelectorAll("[data-theme-mode]").forEach((btn) => {
    const active = btn.dataset.themeMode === mode;
    btn.classList.toggle("active", active);
    btn.setAttribute("aria-checked", active ? "true" : "false");
  });
}

function buildDirectURL(repo, branch, path) {
  const cleanPath = path.replace(/^\/+/, "");
  return `https://raw.githubusercontent.com/${repo}/${branch}/${cleanPath}`;
}

function buildMirrorURL(repo, branch, path) {
  const cleanPath = path.replace(/^\/+/, "");
  return `https://cdn.jsdelivr.net/gh/${repo}@${branch}/${cleanPath}`;
}

function entryTotalDomain(e) {
  return (e.domain || 0) + (e.suffix || 0) + (e.keyword || 0) + (e.regex || 0);
}

function entryTotalRules(e) {
  return entryTotalDomain(e) + (e.ip || 0) + (e.adguard || 0);
}

function getClientCatalog(entry) {
  const m = state.manifest;
  const name = entry.name;
  const hasDomain = entryTotalDomain(entry) > 0;
  const hasIP = (entry.ip || 0) > 0;
  const hasAdGuard = (entry.adguard || 0) > 0;

  const catalog = {};

  const sbVariants = [];
  if (hasDomain) {
    sbVariants.push({ id: "dom-srs", label: hasIP ? "域名 srs" : "srs", repo: m.repo, branch: m.siteBranch, path: `rule_set_site/${name}.srs` });
    sbVariants.push({ id: "dom-json", label: hasIP ? "域名 json" : "json", repo: m.repo, branch: m.siteBranch, path: `rule_set_site/${name}.json` });
  }
  if (hasAdGuard) {
    sbVariants.push({ id: "ag-srs", label: hasDomain || hasIP ? "AdGuard srs" : "srs", repo: m.repo, branch: m.siteBranch, path: `rule_set_site/${name}.srs` });
  }
  if (hasIP) {
    sbVariants.push({ id: "ip-srs", label: hasDomain ? "IP srs" : "srs", repo: m.repo, branch: m.siteBranch, path: `rule_set_ip/${name}.srs` });
    sbVariants.push({ id: "ip-json", label: hasDomain ? "IP json" : "json", repo: m.repo, branch: m.siteBranch, path: `rule_set_ip/${name}.json` });
  }
  if (sbVariants.length > 0) catalog.singbox = sbVariants;

  const mhVariants = [];
  if (hasDomain) {
    mhVariants.push({ id: "dom-mrs", label: hasIP ? "域名 mrs" : "mrs", repo: m.rulesRepo, branch: m.rulesBranch, path: `mihomo/geosite/${name}.mrs` });
    mhVariants.push({ id: "dom-yaml", label: hasIP ? "域名 yaml" : "yaml", repo: m.rulesRepo, branch: m.rulesBranch, path: `mihomo/geosite/${name}.yaml` });
  }
  if (hasIP) {
    mhVariants.push({ id: "ip-mrs", label: hasDomain ? "IP mrs" : "mrs", repo: m.rulesRepo, branch: m.rulesBranch, path: `mihomo/geoip/${name}.mrs` });
    mhVariants.push({ id: "ip-yaml", label: hasDomain ? "IP yaml" : "yaml", repo: m.rulesRepo, branch: m.rulesBranch, path: `mihomo/geoip/${name}.yaml` });
  }
  if (mhVariants.length > 0) catalog.mihomo = mhVariants;

  const surgeVariants = [];
  if (hasDomain) {
    surgeVariants.push({ id: "dom-list", label: hasIP ? "域名 list" : "list", repo: m.rulesRepo, branch: m.rulesBranch, path: `surge/geosite/${name}.list` });
  }
  if (hasIP) {
    surgeVariants.push({ id: "ip-list", label: hasDomain ? "IP list" : "list", repo: m.rulesRepo, branch: m.rulesBranch, path: `surge/geoip/${name}.list` });
  }
  if (surgeVariants.length > 0) catalog.surge = surgeVariants;

  const textVariants = [];
  if (hasDomain) {
    textVariants.push({ id: "dom-txt", label: hasIP ? "域名 txt" : "txt", repo: m.rulesRepo, branch: m.rulesBranch, path: `text/geosite/${name}.txt` });
  }
  if (hasIP) {
    textVariants.push({ id: "ip-txt", label: hasDomain ? "IP txt" : "txt", repo: m.rulesRepo, branch: m.rulesBranch, path: `text/geoip/${name}.txt` });
  }
  if (hasAdGuard && name === "category-ads-all-adguard") {
    textVariants.push({ id: "ag-txt", label: hasDomain || hasIP ? "AdGuard txt" : "txt", repo: m.repo, branch: m.releaseBranch, path: "reject-list-adguard.txt" });
  }
  if (hasAdGuard && name === "awavenue-ads") {
    textVariants.push({ id: "ag-txt", label: hasDomain || hasIP ? "AdGuard txt" : "txt", repo: m.repo, branch: m.releaseBranch, path: "awavenue-ads-adguard.txt" });
  }
  if (textVariants.length > 0) catalog.text = textVariants;

  return catalog;
}

const CLIENT_LABELS = {
  singbox: "sing-box",
  mihomo: "mihomo",
  surge: "Surge",
  text: "Text",
};

function getCardSelection(entry, catalog) {
  const clients = Object.keys(catalog);
  const existing = state.cardSelections.get(entry.name);
  let client = existing?.client;
  if (!client || !catalog[client]) {
    client = catalog[state.defaultClient] ? state.defaultClient : clients[0];
  }
  const variants = catalog[client] || [];
  let variantId = existing?.variantId;
  if (!variantId || !variants.some((v) => v.id === variantId)) {
    variantId = variants[0]?.id || "";
  }
  return { client, variantId };
}

function fnv1a32(str) {
  let hash = 0x811c9dc5;
  const bytes = new TextEncoder().encode(str);
  for (let i = 0; i < bytes.length; i++) {
    hash ^= bytes[i];
    hash = Math.imul(hash, 0x01000193) >>> 0;
  }
  return hash >>> 0;
}

function parseIPv4(str) {
  const parts = str.split(".");
  if (parts.length !== 4) return null;
  let val = 0;
  for (const p of parts) {
    if (!/^\d{1,3}$/.test(p)) return null;
    const n = Number(p);
    if (n < 0 || n > 255) return null;
    val = ((val << 8) | n) >>> 0;
  }
  return val;
}

function parseIPv4CIDR(str) {
  const [ipPart, maskPart] = str.split("/");
  const ip = parseIPv4(ipPart);
  if (ip === null) return null;
  if (maskPart === undefined) return { start: ip, end: ip };
  if (!/^\d{1,2}$/.test(maskPart)) return null;
  const bits = Number(maskPart);
  if (bits < 0 || bits > 32) return null;
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
  const start = (ip & mask) >>> 0;
  const end = (start | (~mask >>> 0)) >>> 0;
  return { start, end };
}

function parseIPv6(str) {
  let s = str.toLowerCase();
  if (s.startsWith("[") && s.endsWith("]")) s = s.slice(1, -1);
  if (!s.includes(":")) return null;
  const dbl = s.split("::");
  if (dbl.length > 2) return null;

  const parseGroups = (part) => {
    if (!part) return [];
    const tokens = part.split(":");
    const out = [];
    for (let i = 0; i < tokens.length; i++) {
      const tok = tokens[i];
      if (tok.includes(".") && i === tokens.length - 1) {
        const v4 = parseIPv4(tok);
        if (v4 === null) return null;
        out.push((v4 >>> 16) & 0xffff, v4 & 0xffff);
      } else {
        if (!/^[0-9a-f]{1,4}$/.test(tok)) return null;
        out.push(parseInt(tok, 16));
      }
    }
    return out;
  };

  let groups;
  if (dbl.length === 2) {
    const left = parseGroups(dbl[0]);
    const right = parseGroups(dbl[1]);
    if (!left || !right) return null;
    const fill = 8 - (left.length + right.length);
    if (fill < 1) return null;
    groups = [...left, ...new Array(fill).fill(0), ...right];
  } else {
    groups = parseGroups(s);
    if (!groups || groups.length !== 8) return null;
  }

  let big = 0n;
  for (const g of groups) {
    big = (big << 16n) | BigInt(g);
  }
  return big;
}

function bigIntToHex32(v) {
  return v.toString(16).padStart(32, "0");
}

function parseIPv6CIDR(str) {
  const [ipPart, maskPart] = str.split("/");
  const ip = parseIPv6(ipPart);
  if (ip === null) return null;
  if (maskPart === undefined) {
    const h = bigIntToHex32(ip);
    return { start: h, end: h };
  }
  if (!/^\d{1,3}$/.test(maskPart)) return null;
  const bits = Number(maskPart);
  if (bits < 0 || bits > 128) return null;
  const full = (1n << 128n) - 1n;
  const hostBits = BigInt(128 - bits);
  const hostMask = (1n << hostBits) - 1n;
  const netMask = full ^ hostMask;
  const start = ip & netMask;
  const end = start | hostMask;
  return { start: bigIntToHex32(start), end: bigIntToHex32(end) };
}

function cleanInput(raw) {
  let q = raw.trim();
  if (!q) return "";
  if (/^https?:\/\//i.test(q)) {
    try {
      q = new URL(q).hostname;
    } catch {
      q = q.replace(/^https?:\/\//i, "").split("/")[0];
    }
  }
  return q.trim();
}

function classifyQuery(raw) {
  const q = cleanInput(raw);
  if (!q) return { mode: "idle", value: "" };

  const v4 = parseIPv4CIDR(q);
  if (v4) return { mode: "ipv4", value: q, range: v4 };

  const v6 = parseIPv6CIDR(q);
  if (v6) return { mode: "ipv6", value: q, range: v6 };

  const lower = q.toLowerCase().replace(/^\.+|\.+$/g, "");
  if (lower.includes(".") && /^[a-z0-9-]+(\.[a-z0-9-]+)+$/.test(lower)) {
    return { mode: "domain", value: lower };
  }

  return { mode: "filter", value: lower };
}

async function fetchJSON(url) {
  const resp = await fetch(url);
  if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
  return resp.json();
}

async function getShard(index) {
  if (state.shardCache.has(index)) return state.shardCache.get(index);
  const hex = index.toString(16).padStart(2, "0");
  const promise = fetchJSON(`./data/shards/d_${hex}.json`);
  state.shardCache.set(index, promise);
  return promise;
}

async function getSpecial() {
  if (!state.specialData) state.specialData = fetchJSON("./data/special.json");
  return state.specialData;
}

async function getIPv4() {
  if (!state.ipv4Data) state.ipv4Data = fetchJSON("./data/ip_v4.json");
  return state.ipv4Data;
}

async function getIPv6() {
  if (!state.ipv6Data) state.ipv6Data = fetchJSON("./data/ip_v6.json");
  return state.ipv6Data;
}

async function lookupDomain(domain) {
  const shardCount = state.manifest.shardCount || 64;
  const labels = domain.split(".");
  const suffixes = [];
  for (let i = 0; i < labels.length; i++) {
    suffixes.push(labels.slice(i).join("."));
  }

  const shardIndices = new Set();
  for (const s of suffixes) {
    shardIndices.add(fnv1a32(s) % shardCount);
  }

  const [loadedShards, special] = await Promise.all([
    Promise.all([...shardIndices].map(async (idx) => [idx, await getShard(idx)])),
    getSpecial(),
  ]);
  const shardMap = new Map(loadedShards);

  const hits = new Map();
  const addHit = (id, kind, rule) => {
    if (!hits.has(id)) hits.set(id, []);
    const list = hits.get(id);
    if (!list.some((r) => r.kind === kind && r.rule === rule)) {
      list.push({ kind, rule });
    }
  };

  const exactShard = shardMap.get(fnv1a32(domain) % shardCount);
  if (exactShard && exactShard.e && exactShard.e[domain]) {
    for (const id of exactShard.e[domain]) addHit(id, "domain", domain);
  }

  for (const suffix of suffixes) {
    const sh = shardMap.get(fnv1a32(suffix) % shardCount);
    if (sh && sh.s && sh.s[suffix]) {
      for (const id of sh.s[suffix]) addHit(id, "domain_suffix", suffix);
    }
  }

  if (special.k) {
    for (const [kw, ids] of special.k) {
      if (domain.includes(kw)) {
        for (const id of ids) addHit(id, "domain_keyword", kw);
      }
    }
  }

  if (special.r) {
    for (const [pattern, ids] of special.r) {
      try {
        if (new RegExp(pattern, "i").test(domain)) {
          for (const id of ids) addHit(id, "domain_regex", pattern);
        }
      } catch {
      }
    }
  }

  return [...hits.entries()]
    .map(([id, reasons]) => ({ entry: state.entryById.get(id), reasons }))
    .filter((item) => item.entry)
    .sort((a, b) => a.entry.name.localeCompare(b.entry.name));
}

async function lookupIPv4(range) {
  const rows = await getIPv4();
  const hits = new Map();
  for (let i = 0; i < rows.length; i++) {
    const [start, end, cidr, ids] = rows[i];
    if (start > range.end) break;
    if (end >= range.start) {
      for (const id of ids) {
        if (!hits.has(id)) hits.set(id, []);
        hits.get(id).push({ kind: "ip_cidr", rule: cidr });
      }
    }
  }
  return [...hits.entries()]
    .map(([id, reasons]) => ({ entry: state.entryById.get(id), reasons }))
    .filter((item) => item.entry)
    .sort((a, b) => a.entry.name.localeCompare(b.entry.name));
}

async function lookupIPv6(range) {
  const rows = await getIPv6();
  const hits = new Map();
  for (let i = 0; i < rows.length; i++) {
    const [start, end, cidr, ids] = rows[i];
    if (start > range.end) break;
    if (end >= range.start) {
      for (const id of ids) {
        if (!hits.has(id)) hits.set(id, []);
        hits.get(id).push({ kind: "ip_cidr", rule: cidr });
      }
    }
  }
  return [...hits.entries()]
    .map(([id, reasons]) => ({ entry: state.entryById.get(id), reasons }))
    .filter((item) => item.entry)
    .sort((a, b) => a.entry.name.localeCompare(b.entry.name));
}

const SAMPLE_DOMAINS = [
  "www.youtube.com",
  "bilibili.com",
  "github.com",
  "chat.openai.com",
  "discord.com",
  "netflix.com",
  "spotify.com",
  "apple.com",
  "claude.ai",
  "tiktok.com",
  "instagram.com",
  "zhihu.com",
  "cloudflare.com",
  "telegram.org",
];

const SAMPLE_IPS = [
  "91.108.4.1",
  "1.1.1.1",
  "8.8.8.8",
  "114.114.114.114",
  "2001:67c:4e8::1",
  "2400:3200::1",
];

function pickRandomItems(arr, count) {
  const pool = [...arr];
  for (let i = pool.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [pool[i], pool[j]] = [pool[j], pool[i]];
  }
  return pool.slice(0, count);
}

function renderRandomSuggestions() {
  const dom = pickRandomItems(SAMPLE_DOMAINS, 1);
  const ip = pickRandomItems(SAMPLE_IPS, 1);
  const rulePool = state.manifest.entries
    .filter((e) => e.name.length <= 16 && !e.name.includes("@") && entryTotalRules(e) >= 10)
    .map((e) => e.name);
  const rules = pickRandomItems(rulePool, 3);
  const items = pickRandomItems([...dom, ...ip, ...rules], 5);

  el.suggestionsBar.querySelectorAll("[data-example]").forEach((node) => node.remove());
  for (const val of items) {
    const btn = document.createElement("button");
    btn.className = "suggestion-chip";
    btn.type = "button";
    btn.dataset.example = val;
    btn.textContent = val;
    el.suggestionsBar.insertBefore(btn, el.browseAllBtn);
  }
}

function renderSummary() {
  const t = state.manifest.totals;
  el.summaryLine.textContent = `${t.entries.toLocaleString()} 个规则集 · ${t.domainRules.toLocaleString()} 条域名 · ${t.ipRanges.toLocaleString()} 条 IP 段 · ${t.adguardRules.toLocaleString()} 条 AdGuard`;
}

function renderMetaTagsHTML(entry) {
  const parts = [];
  const dom = entryTotalDomain(entry);
  if (dom > 0) parts.push(`<span class="meta-item"><span class="meta-dot dot-domain"></span>Domain ${dom.toLocaleString()}</span>`);
  if ((entry.ip || 0) > 0) parts.push(`<span class="meta-item"><span class="meta-dot dot-ip"></span>IP ${entry.ip.toLocaleString()}</span>`);
  if ((entry.adguard || 0) > 0) parts.push(`<span class="meta-item"><span class="meta-dot dot-adguard"></span>AdGuard ${entry.adguard.toLocaleString()}</span>`);
  return parts.join("");
}

function renderHighlightedHit(reason, queryValue) {
  const rule = reason.rule;
  if (!queryValue) return escapeHTML(rule);
  if (reason.kind === "domain" && queryValue === rule) {
    return `<mark>${escapeHTML(queryValue)}</mark>`;
  }
  if (reason.kind === "domain_suffix" && queryValue.endsWith(rule)) {
    const prefixLen = queryValue.length - rule.length;
    const prefix = queryValue.slice(0, prefixLen);
    return `${escapeHTML(prefix)}<mark>${escapeHTML(rule)}</mark>`;
  }
  if (reason.kind === "domain_keyword") {
    const idx = queryValue.indexOf(rule);
    if (idx !== -1) {
      return `${escapeHTML(queryValue.slice(0, idx))}<mark>${escapeHTML(rule)}</mark>${escapeHTML(queryValue.slice(idx + rule.length))}`;
    }
  }
  return escapeHTML(rule);
}

function buildRuleCardHTML(entry, reasons = null, queryValue = "") {
  const catalog = getClientCatalog(entry);
  const clients = Object.keys(catalog);
  const { client, variantId } = getCardSelection(entry, catalog);
  const variants = catalog[client] || [];
  const current = variants.find((v) => v.id === variantId) || variants[0];

  const directURL = current ? buildDirectURL(current.repo, current.branch, current.path) : "";
  const mirrorURL = current ? buildMirrorURL(current.repo, current.branch, current.path) : "";

  const clientButtons = clients
    .map((c) => `<button class="client-tab${c === client ? " active" : ""}" type="button" data-card-client="${c}" data-entry="${escapeAttr(entry.name)}">${CLIENT_LABELS[c]}</button>`)
    .join("");

  const variantButtons = variants
    .map((v) => `<button class="format-chip${v.id === current?.id ? " active" : ""}" type="button" data-card-variant="${escapeAttr(v.id)}" data-entry="${escapeAttr(entry.name)}">${escapeHTML(v.label)}</button>`)
    .join("");

  const hitBlock =
    reasons && reasons.length > 0
      ? `<div class="hit-trace">${reasons
          .slice(0, 3)
          .map((r) => `<div class="hit-line"><span class="hit-kind">${escapeHTML(r.kind)}</span><span class="hit-value">${renderHighlightedHit(r, queryValue)}</span></div>`)
          .join("")}</div>`
      : "";

  return `<article class="rule-card" data-entry-card="${escapeAttr(entry.name)}">
    <div class="card-content">
      <div class="card-head">
        <div class="card-title-group">
          <button class="card-title-btn" type="button" data-open-entry="${escapeAttr(entry.name)}">${escapeHTML(entry.name)}</button>
          <div class="meta-tags">${renderMetaTagsHTML(entry)}</div>
        </div>
        <button class="detail-ghost-btn" type="button" data-open-entry="${escapeAttr(entry.name)}"><span>详情</span>${CHEVRON_SVG}</button>
      </div>
      ${hitBlock}
      <div class="card-controls">
        <div class="client-tabs" role="tablist" aria-label="选择客户端">${clientButtons}</div>
        <div class="format-row">${variantButtons}</div>
      </div>
      <div class="card-actions">
        <button class="split-copy-btn" type="button" data-copy-url="${escapeAttr(directURL)}" title="复制 GitHub Raw 直链">
          <span class="copy-head"><span class="copy-icon">${LINK_SVG}</span><span class="copy-label">直链</span></span>
          <span class="copy-state">复制</span>
        </button>
        <button class="split-copy-btn is-mirror" type="button" data-copy-url="${escapeAttr(mirrorURL)}" title="复制 jsDelivr 镜像源">
          <span class="copy-head"><span class="copy-icon">${MIRROR_SVG}</span><span class="copy-label">镜像源</span></span>
          <span class="copy-state">复制</span>
        </button>
      </div>
    </div>
  </article>`;
}

function refreshCardsForEntry(name) {
  const entry = state.entryByName.get(name.toLowerCase());
  if (!entry) return;
  const ctx = state.renderedEntries.get(entry.name) || { reasons: null, queryValue: "" };
  document.querySelectorAll(`[data-entry-card="${CSS.escape(entry.name)}"]`).forEach((cardEl) => {
    const wrapper = document.createElement("div");
    wrapper.innerHTML = buildRuleCardHTML(entry, ctx.reasons, ctx.queryValue);
    cardEl.replaceWith(wrapper.firstElementChild);
  });
}

function setIdleState(idle) {
  document.body.classList.toggle("is-idle", idle);
  el.resultsSection.classList.toggle("hidden", idle);
  el.kbdHint.classList.toggle("hidden", !idle);
}

function filterEntriesByKeyword(kw) {
  let list = state.manifest.entries;
  if (state.filterKind === "domain") list = list.filter((e) => entryTotalDomain(e) > 0);
  else if (state.filterKind === "ip") list = list.filter((e) => (e.ip || 0) > 0);
  else if (state.filterKind === "adguard") list = list.filter((e) => (e.adguard || 0) > 0);

  if (kw) {
    list = list
      .filter((e) => e.name.includes(kw))
      .sort((a, b) => {
        const aExact = a.name === kw ? 0 : a.name.startsWith(kw) ? 1 : 2;
        const bExact = b.name === kw ? 0 : b.name.startsWith(kw) ? 1 : 2;
        if (aExact !== bExact) return aExact - bExact;
        return a.name.localeCompare(b.name);
      });
  } else {
    list = [...list].sort((a, b) => a.name.localeCompare(b.name));
  }
  return list;
}

function renderFilterResults(kw) {
  const list = filterEntriesByKeyword(kw);
  state.renderedEntries.clear();

  el.resultsHeading.textContent = kw ? `包含 “${kw}” 的规则集` : "全部规则集";
  el.resultsMeta.textContent = `共 ${list.length.toLocaleString()} 个`;
  el.resultsTools.classList.remove("hidden");

  const slice = list.slice(0, state.resultLimit);
  if (slice.length === 0) {
    el.resultsGrid.innerHTML = `<div class="empty-state">没有找到匹配的规则集，试试换个关键词或输入完整域名 / IP。</div>`;
    el.resultsFooter.classList.add("hidden");
    return;
  }

  for (const entry of slice) {
    state.renderedEntries.set(entry.name, { reasons: null, queryValue: "" });
  }
  el.resultsGrid.innerHTML = slice.map((entry) => buildRuleCardHTML(entry)).join("");

  if (list.length > state.resultLimit) {
    el.resultsFooter.classList.remove("hidden");
    el.loadMoreBtn.textContent = `显示更多（剩余 ${(list.length - state.resultLimit).toLocaleString()} 个）`;
  } else {
    el.resultsFooter.classList.add("hidden");
  }
}

function renderMatchResults(info, hits, elapsedMs) {
  state.renderedEntries.clear();
  el.resultsHeading.textContent = info.value;
  el.resultsMeta.textContent = `命中 ${hits.length} 个规则集 · ${elapsedMs} ms`;
  el.resultsTools.classList.add("hidden");
  el.resultsFooter.classList.add("hidden");

  if (hits.length === 0) {
    el.resultsGrid.innerHTML = `<div class="empty-state">未命中任何规则集：${escapeHTML(info.value)}</div>`;
    return;
  }

  for (const item of hits) {
    state.renderedEntries.set(item.entry.name, { reasons: item.reasons, queryValue: info.value });
  }
  el.resultsGrid.innerHTML = hits.map((item) => buildRuleCardHTML(item.entry, item.reasons, info.value)).join("");
}

function buildSnippet(entry, client, source) {
  const m = state.manifest;
  const name = entry.name;
  const hasDomain = entryTotalDomain(entry) > 0;
  const hasIP = (entry.ip || 0) > 0;
  const hasAdGuard = (entry.adguard || 0) > 0;
  const urlFor = (repo, branch, path) => (source === "mirror" ? buildMirrorURL(repo, branch, path) : buildDirectURL(repo, branch, path));

  if (client === "singbox") {
    const items = [];
    if (hasDomain || hasAdGuard) {
      items.push({
        tag: `geosite-${name}`,
        type: "remote",
        format: "binary",
        url: urlFor(m.repo, m.siteBranch, `rule_set_site/${name}.srs`),
      });
    }
    if (hasIP) {
      items.push({
        tag: `geoip-${name}`,
        type: "remote",
        format: "binary",
        url: urlFor(m.repo, m.siteBranch, `rule_set_ip/${name}.srs`),
      });
    }
    return JSON.stringify({ route: { rule_set: items } }, null, 2);
  }

  if (client === "mihomo") {
    const lines = ["rule-providers:"];
    if (hasDomain) {
      lines.push(
        `  geosite-${name}:`,
        `    type: http`,
        `    behavior: domain`,
        `    format: mrs`,
        `    url: "${urlFor(m.rulesRepo, m.rulesBranch, `mihomo/geosite/${name}.mrs`)}"`,
        `    interval: 86400`
      );
    }
    if (hasIP) {
      lines.push(
        `  geoip-${name}:`,
        `    type: http`,
        `    behavior: ipcidr`,
        `    format: mrs`,
        `    url: "${urlFor(m.rulesRepo, m.rulesBranch, `mihomo/geoip/${name}.mrs`)}"`,
        `    interval: 86400`
      );
    }
    return lines.length > 1 ? lines.join("\n") : "# 当前规则集不包含 mihomo 格式产物";
  }

  const surgeLines = [];
  if (hasDomain) {
    surgeLines.push(`RULE-SET,${urlFor(m.rulesRepo, m.rulesBranch, `surge/geosite/${name}.list`)},PROXY`);
  }
  if (hasIP) {
    surgeLines.push(`RULE-SET,${urlFor(m.rulesRepo, m.rulesBranch, `surge/geoip/${name}.list`)},PROXY,no-resolve`);
  }
  return surgeLines.join("\n") || "# 当前规则集不包含 Surge 格式产物";
}

function renderDrawerSnippet() {
  if (!state.activeEntry) return;
  el.snippetCode.textContent = buildSnippet(state.activeEntry, state.activeSnippet, state.snippetSource);
}

async function loadRulePreview(entry, kind) {
  state.previewRows = [];
  state.previewLimit = 100;
  el.previewList.innerHTML = "";
  el.previewPager.classList.add("hidden");

  if (kind === "adguard") {
    el.previewStatus.textContent = "AdGuard 规则集以编译后的 srs 提供，原始文本可在 release 分支查看。";
    return;
  }

  const m = state.manifest;
  const subPath = kind === "ip" ? `rule_set_ip/${entry.name}.json` : `rule_set_site/${entry.name}.json`;
  const candidates = [
    `./rule_set/${subPath}`,
    buildMirrorURL(m.repo, m.siteBranch, subPath),
    buildDirectURL(m.repo, m.siteBranch, subPath),
  ];

  el.previewStatus.textContent = "正在加载规则明细…";
  let doc = null;
  for (const url of candidates) {
    try {
      const resp = await fetch(url);
      if (resp.ok) {
        doc = await resp.json();
        break;
      }
    } catch {
    }
  }

  if (!doc || !Array.isArray(doc.rules)) {
    el.previewStatus.textContent = "无法拉取规则明细 JSON，请检查网络连接。";
    return;
  }

  const rows = [];
  for (const rule of doc.rules) {
    for (const field of ["domain", "domain_suffix", "domain_keyword", "domain_regex", "ip_cidr"]) {
      const vals = rule[field];
      if (!vals) continue;
      const arr = Array.isArray(vals) ? vals : [vals];
      for (const v of arr) rows.push({ type: field, value: String(v) });
    }
  }
  state.previewRows = rows;
  renderPreviewRows();
}

function renderPreviewRows() {
  const kw = el.previewSearchInput.value.trim().toLowerCase();
  const filtered = kw
    ? state.previewRows.filter((r) => r.value.toLowerCase().includes(kw) || r.type.includes(kw))
    : state.previewRows;

  el.previewStatus.textContent = `共 ${filtered.length.toLocaleString()} 条规则`;
  const slice = filtered.slice(0, state.previewLimit);
  if (slice.length === 0) {
    el.previewList.innerHTML = `<div class="preview-item">无匹配条目</div>`;
    el.previewPager.classList.add("hidden");
    return;
  }

  el.previewList.innerHTML = slice
    .map((r) => `<div class="preview-item"><span class="preview-type">${escapeHTML(r.type)}</span><span>${escapeHTML(r.value)}</span></div>`)
    .join("");

  if (filtered.length > state.previewLimit) {
    el.previewPager.classList.remove("hidden");
    el.previewMoreBtn.textContent = `加载更多条目（剩余 ${(filtered.length - state.previewLimit).toLocaleString()} 条）`;
  } else {
    el.previewPager.classList.add("hidden");
  }
}

function openDrawer(name) {
  const entry = state.entryByName.get(name.toLowerCase());
  if (!entry) return;

  state.activeEntry = entry;
  el.drawerTitle.textContent = entry.name;
  el.drawerMeta.innerHTML = renderMetaTagsHTML(entry);
  el.previewSearchInput.value = "";
  renderDrawerSnippet();

  const kinds = [];
  if (entryTotalDomain(entry) > 0) kinds.push({ value: "domain", label: "域名规则" });
  if ((entry.ip || 0) > 0) kinds.push({ value: "ip", label: "IP 规则" });
  if ((entry.adguard || 0) > 0) kinds.push({ value: "adguard", label: "AdGuard" });

  el.previewKindSelect.innerHTML = kinds.map((k) => `<option value="${k.value}">${k.label}</option>`).join("");
  el.previewKindSelect.classList.toggle("hidden", kinds.length <= 1);

  el.drawerBackdrop.classList.add("is-open");
  el.detailDrawer.classList.add("is-open");
  document.body.classList.add("drawer-open");
  el.detailDrawer.setAttribute("aria-hidden", "false");
  const bodyEl = el.detailDrawer.querySelector(".drawer-body");
  if (bodyEl) bodyEl.scrollTop = 0;

  if (kinds.length > 0) loadRulePreview(entry, kinds[0].value);
}

function closeDrawer() {
  state.activeEntry = null;
  el.drawerBackdrop.classList.remove("is-open");
  el.detailDrawer.classList.remove("is-open");
  document.body.classList.remove("drawer-open");
  el.detailDrawer.setAttribute("aria-hidden", "true");
}

function setModeBadge(text, mode) {
  if (!text) {
    el.queryModeTag.classList.add("hidden");
    el.queryModeTag.textContent = "";
    el.queryModeTag.dataset.mode = "";
    return;
  }
  el.queryModeTag.textContent = text;
  el.queryModeTag.dataset.mode = mode;
  el.queryModeTag.classList.remove("hidden");
}

async function handleQueryChange() {
  if (!state.manifest) return;
  const raw = el.queryInput.value;
  el.clearQueryBtn.classList.toggle("hidden", !raw && !state.browseAll);
  const info = classifyQuery(raw);

  if (info.mode === "idle") {
    if (state.browseAll) {
      setModeBadge("全部", "filter");
      setIdleState(false);
      renderFilterResults("");
      return;
    }
    setModeBadge("", "");
    setIdleState(true);
    return;
  }

  state.browseAll = false;
  setIdleState(false);

  if (info.mode === "filter") {
    setModeBadge("规则", "filter");
    state.resultLimit = 36;
    renderFilterResults(info.value);
    return;
  }

  if (info.mode === "domain") {
    setModeBadge("域名", "domain");
  } else {
    setModeBadge(info.mode === "ipv4" ? "IPv4" : "IPv6", "ip");
  }

  const seq = ++state.querySeq;
  const start = performance.now();
  el.resultsHeading.textContent = info.value;
  el.resultsMeta.textContent = "查询中…";
  el.resultsTools.classList.add("hidden");
  el.resultsFooter.classList.add("hidden");

  try {
    let hits;
    if (info.mode === "domain") {
      hits = await lookupDomain(info.value);
    } else if (info.mode === "ipv4") {
      hits = await lookupIPv4(info.range);
    } else {
      hits = await lookupIPv6(info.range);
    }
    if (seq !== state.querySeq) return;
    renderMatchResults(info, hits, Math.max(1, Math.round(performance.now() - start)));
  } catch (err) {
    if (seq !== state.querySeq) return;
    el.resultsHeading.textContent = info.value;
    el.resultsMeta.textContent = "查询失败";
    el.resultsGrid.innerHTML = `<div class="empty-state">索引加载失败（${escapeHTML(err.message)}），请确认数据已构建。</div>`;
  }
}

function resetToIdle() {
  state.browseAll = false;
  state.filterKind = "all";
  state.resultLimit = 36;
  document.querySelectorAll("[data-filter]").forEach((b) => {
    const active = b.dataset.filter === "all";
    b.classList.toggle("active", active);
    b.setAttribute("aria-selected", active ? "true" : "false");
  });
  el.queryInput.value = "";
  handleQueryChange();
  el.queryInput.focus();
}

function escapeHTML(str) {
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function escapeAttr(str) {
  return escapeHTML(str).replace(/'/g, "&#39;");
}

function bindEvents() {
  let debounceTimer = null;
  el.queryInput.addEventListener("input", () => {
    clearTimeout(debounceTimer);
    debounceTimer = setTimeout(handleQueryChange, 110);
  });

  el.clearQueryBtn.addEventListener("click", resetToIdle);
  el.brandResetBtn.addEventListener("click", resetToIdle);

  el.suggestionsBar.addEventListener("click", (ev) => {
    const btn = ev.target.closest("[data-example]");
    if (!btn) return;
    state.browseAll = false;
    el.queryInput.value = btn.dataset.example;
    handleQueryChange();
    el.queryInput.focus();
  });

  el.browseAllBtn.addEventListener("click", () => {
    state.browseAll = true;
    state.resultLimit = 36;
    el.queryInput.value = "";
    handleQueryChange();
  });

  document.querySelectorAll("[data-filter]").forEach((btn) => {
    btn.addEventListener("click", () => {
      document.querySelectorAll("[data-filter]").forEach((b) => {
        b.classList.remove("active");
        b.setAttribute("aria-selected", "false");
      });
      btn.classList.add("active");
      btn.setAttribute("aria-selected", "true");
      state.filterKind = btn.dataset.filter;
      state.resultLimit = 36;
      const info = classifyQuery(el.queryInput.value);
      renderFilterResults(info.mode === "filter" ? info.value : "");
    });
  });

  el.loadMoreBtn.addEventListener("click", () => {
    state.resultLimit += 48;
    const info = classifyQuery(el.queryInput.value);
    renderFilterResults(info.mode === "filter" ? info.value : "");
  });

  document.querySelectorAll("[data-theme-mode]").forEach((btn) => {
    btn.addEventListener("click", () => {
      applyThemeMode(btn.dataset.themeMode);
    });
  });

  el.resultsGrid.addEventListener("pointermove", (ev) => {
    const card = ev.target.closest(".rule-card");
    if (!card) return;
    const rect = card.getBoundingClientRect();
    card.style.setProperty("--mx", `${ev.clientX - rect.left}px`);
    card.style.setProperty("--my", `${ev.clientY - rect.top}px`);
  });

  document.addEventListener("click", (ev) => {
    const clientBtn = ev.target.closest("[data-card-client]");
    if (clientBtn) {
      const name = clientBtn.dataset.entry;
      const client = clientBtn.dataset.cardClient;
      state.cardSelections.set(name, { client, variantId: "" });
      refreshCardsForEntry(name);
      return;
    }

    const variantBtn = ev.target.closest("[data-card-variant]");
    if (variantBtn) {
      const name = variantBtn.dataset.entry;
      const variantId = variantBtn.dataset.cardVariant;
      const cur = state.cardSelections.get(name) || { client: state.defaultClient };
      state.cardSelections.set(name, { client: cur.client, variantId });
      refreshCardsForEntry(name);
      return;
    }

    const copyBtn = ev.target.closest("[data-copy-url]");
    if (copyBtn) {
      copyText(copyBtn.dataset.copyUrl, copyBtn);
      return;
    }

    const openBtn = ev.target.closest("[data-open-entry]");
    if (openBtn) {
      openDrawer(openBtn.dataset.openEntry);
    }
  });

  document.querySelectorAll("[data-snippet]").forEach((btn) => {
    btn.addEventListener("click", () => {
      document.querySelectorAll("[data-snippet]").forEach((b) => b.classList.remove("active"));
      btn.classList.add("active");
      state.activeSnippet = btn.dataset.snippet;
      renderDrawerSnippet();
    });
  });

  document.querySelectorAll("[data-snippet-source]").forEach((btn) => {
    btn.addEventListener("click", () => {
      document.querySelectorAll("[data-snippet-source]").forEach((b) => b.classList.remove("active"));
      btn.classList.add("active");
      state.snippetSource = btn.dataset.snippetSource;
      renderDrawerSnippet();
    });
  });

  el.copySnippetBtn.dataset.defaultText = "复制片段";
  el.copySnippetBtn.addEventListener("click", () => {
    copyText(el.snippetCode.textContent, el.copySnippetBtn);
  });

  el.previewKindSelect.addEventListener("change", () => {
    if (state.activeEntry) loadRulePreview(state.activeEntry, el.previewKindSelect.value);
  });

  el.previewSearchInput.addEventListener("input", () => {
    state.previewLimit = 100;
    renderPreviewRows();
  });

  el.previewMoreBtn.addEventListener("click", () => {
    state.previewLimit += 150;
    renderPreviewRows();
  });

  el.closeDrawerBtn.addEventListener("click", closeDrawer);
  el.drawerBackdrop.addEventListener("click", closeDrawer);

  document.addEventListener("keydown", (ev) => {
    if (ev.key === "Escape") {
      if (state.activeEntry) {
        closeDrawer();
        return;
      }
      if (!document.body.classList.contains("is-idle")) {
        resetToIdle();
        return;
      }
    }
    if (ev.key === "/" && document.activeElement !== el.queryInput && document.activeElement.tagName !== "INPUT") {
      ev.preventDefault();
      el.queryInput.focus();
      el.queryInput.select();
    }
  });
}

async function boot() {
  initTheme();
  bindEvents();

  try {
    const manifest = await fetchJSON("./data/manifest.json");
    state.manifest = manifest;
    for (const entry of manifest.entries) {
      state.entryById.set(entry.id, entry);
      state.entryByName.set(entry.name.toLowerCase(), entry);
    }
    renderSummary();
    renderRandomSuggestions();

    const params = new URLSearchParams(window.location.search);
    const initialQ = params.get("q");
    if (initialQ) {
      el.queryInput.value = initialQ;
      handleQueryChange();
    }
  } catch (err) {
    el.summaryLine.textContent = `索引加载失败（${err.message}），请先构建索引数据`;
  }
}

boot();
