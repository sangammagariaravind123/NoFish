function ensureUrl(value) {
  try {
    return new URL(value);
  } catch (error) {
    return null;
  }
}

export function safeUrl(value) {
  return ensureUrl(value);
}

export function normalizeUrl(url) {
  const parsed = ensureUrl(url);
  if (!parsed) return String(url || "").trim();
  parsed.hash = "";
  return parsed.toString();
}

export function getDomain(url) {
  const parsed = ensureUrl(url);
  if (!parsed) return "";
  return parsed.hostname.toLowerCase();
}

export function getBaseDomain(url) {
  const host = getDomain(url);
  if (!host) return "";
  return host.replace(/^www\./, "");
}

export function getDisplayDomain(url) {
  return getBaseDomain(url) || url;
}

export function matchesDomain(hostname, ruleValue) {
  const host = String(hostname || "").toLowerCase();
  const rule = String(ruleValue || "").toLowerCase().replace(/^www\./, "");
  if (!host || !rule) return false;
  return host === rule || host.endsWith(`.${rule}`);
}

export function matchesRule(url, rule) {
  const targetUrl = normalizeUrl(url).toLowerCase();
  const hostname = getBaseDomain(url);
  const value = String(rule?.value || "").trim().toLowerCase();
  if (!value) return false;

  switch (rule?.type) {
    case "domain":
      return matchesDomain(hostname, value);
    case "url":
      return targetUrl === normalizeUrl(value).toLowerCase();
    case "suffix":
      return hostname.endsWith(value.replace(/^\*\./, ""));
    case "keyword":
      return targetUrl.includes(value);
    default:
      return false;
  }
}

export function makeDomainRule(value, remoteId = null, source = "remote") {
  return {
    id: remoteId || crypto.randomUUID(),
    type: "domain",
    value: String(value || "").trim().toLowerCase(),
    source,
    remoteId,
    createdAt: new Date().toISOString()
  };
}
