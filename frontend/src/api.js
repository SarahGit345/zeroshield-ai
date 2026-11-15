export const API = 'http://localhost:8000/api';

export async function getJson(path) {
  const r = await fetch(`${API}${path}`);
  const data = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(errorText(data, r.status));
  return data;
}

export async function postJson(path, body) {
  const r = await fetch(`${API}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const data = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(errorText(data, r.status));
  return data;
}

function errorText(data, status) {
  const d = data?.detail;
  if (typeof d === 'string') return d;
  if (d?.message) return d.message;
  if (Array.isArray(d)) return d.map(x => x.msg).join('; ');
  return `Request failed (${status})`;
}

export const ACTION_LABELS = {
  AUTO_REMEDIATE: 'Auto-contain (simulated)',
  CONFIRM_TO_ACT: 'Contain after approval',
  HUMAN_REVIEW: 'Analyst review',
  MONITOR_ONLY: 'Monitor only',
};

export const ACTION_COLORS = {
  AUTO_REMEDIATE: '#ff7a85',
  CONFIRM_TO_ACT: '#f4be70',
  HUMAN_REVIEW: '#70a9ff',
  MONITOR_ONLY: '#5f7389',
};

export const fmt = (v, d = 4) => (v === null || v === undefined || Number.isNaN(Number(v)) ? '—' : Number(v).toFixed(d));
export const pct = (k, n, d = 1) => (n ? `${((100 * k) / n).toFixed(d)}%` : '—');
