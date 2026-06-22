// Thin wrapper over the backend REST API. All paths go through the Vite proxy to FastAPI.

async function handle(res) {
  if (res.status === 204) return null
  const body = await res.json().catch(() => ({}))
  if (!res.ok) throw new Error(body.detail || res.statusText)
  return body
}

const post = (path, body) =>
  fetch(path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  }).then(handle)

export const api = {
  stats: () => fetch('/api/stats').then(handle),
  listTargets: () => fetch('/api/targets').then(handle),
  getTarget: (id) => fetch(`/api/targets/${id}`).then(handle),
  createTarget: (t) => post('/api/targets', t),
  deleteTarget: (id) => fetch(`/api/targets/${id}`, { method: 'DELETE' }).then(handle),
  triggerScan: (id) => post(`/api/targets/${id}/scan`),
  listScans: (targetId) =>
    fetch(`/api/scans${targetId ? `?target_id=${targetId}` : ''}`).then(handle),
  getScan: (id) => fetch(`/api/scans/${id}`).then(handle),
  trend: (id) => fetch(`/api/targets/${id}/trend`).then(handle),
  listSuppressions: () => fetch('/api/suppressions').then(handle),
  suppress: (fingerprint, reason) => post('/api/suppressions', { fingerprint, reason }),
  unsuppress: (fp) => fetch(`/api/suppressions/${fp}`, { method: 'DELETE' }).then(handle),
}

export const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info']
