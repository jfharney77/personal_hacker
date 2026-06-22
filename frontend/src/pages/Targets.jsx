import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { api } from '../api.js'

const BLANK = {
  name: '', target_urls: '', allowlist: 'localhost, 127.0.0.1', repo_path: '',
  safe_mode: true, offline: false, ssrf_canary: false, i_own_this: false,
}

export default function Targets() {
  const [targets, setTargets] = useState([])
  const [form, setForm] = useState(BLANK)
  const [busy, setBusy] = useState(null)
  const [err, setErr] = useState(null)
  const nav = useNavigate()

  const load = () => api.listTargets().then(setTargets).catch((e) => setErr(e.message))
  useEffect(() => { load() }, [])

  const csv = (s) => s.split(',').map((x) => x.trim()).filter(Boolean)

  async function submit(e) {
    e.preventDefault()
    setErr(null)
    try {
      await api.createTarget({
        name: form.name,
        target_urls: csv(form.target_urls),
        allowlist: csv(form.allowlist),
        repo_path: form.repo_path || null,
        safe_mode: form.safe_mode, offline: form.offline,
        ssrf_canary: form.ssrf_canary, i_own_this: form.i_own_this,
      })
      setForm(BLANK)
      load()
    } catch (e) { setErr(e.message) }
  }

  async function runScan(id) {
    setBusy(id)
    try {
      const scan = await api.triggerScan(id)
      // Poll until the background scan finishes, then jump to its detail page.
      let s = scan
      while (s.status === 'pending' || s.status === 'running') {
        await new Promise((r) => setTimeout(r, 800))
        s = await api.getScan(scan.id).then((d) => d.scan)
      }
      nav(`/scans/${scan.id}`)
    } catch (e) { setErr(e.message) } finally { setBusy(null) }
  }

  async function remove(id) {
    if (!confirm('Delete this target and all its scans?')) return
    await api.deleteTarget(id)
    load()
  }

  const set = (k) => (e) => setForm({ ...form, [k]: e.target.type === 'checkbox' ? e.target.checked : e.target.value })

  return (
    <>
      <h1>Targets</h1>

      <div className="panel">
        <h2 style={{ marginTop: 0 }}>Add a target</h2>
        {err && <p className="status-error">{err}</p>}
        <form onSubmit={submit}>
          <label className="field"><span>Name</span>
            <input value={form.name} onChange={set('name')} placeholder="my-app (staging)" required /></label>
          <label className="field"><span>Target URLs (comma-separated, for live/DAST scans)</span>
            <input value={form.target_urls} onChange={set('target_urls')} placeholder="http://localhost:8000" /></label>
          <label className="field"><span>Allowlist (hosts the scanner may touch)</span>
            <input value={form.allowlist} onChange={set('allowlist')} /></label>
          <label className="field"><span>Repo path (for source/SAST scans, optional)</span>
            <input value={form.repo_path} onChange={set('repo_path')} placeholder="/home/john/github/my-app" /></label>
          <div className="row" style={{ marginBottom: 14 }}>
            <label className="check"><input type="checkbox" checked={form.safe_mode} onChange={set('safe_mode')} /> safe mode</label>
            <label className="check"><input type="checkbox" checked={form.offline} onChange={set('offline')} /> offline</label>
            <label className="check"><input type="checkbox" checked={form.ssrf_canary} onChange={set('ssrf_canary')} /> SSRF canary</label>
            <label className="check"><input type="checkbox" checked={form.i_own_this} onChange={set('i_own_this')} /> I own this (non-local)</label>
          </div>
          <button type="submit">Add target</button>
        </form>
      </div>

      <h2>Configured targets</h2>
      {targets.length === 0 ? <p className="muted">None yet.</p> : targets.map((t) => (
        <div className="panel spread" key={t.id}>
          <div>
            <div style={{ fontWeight: 600 }}>{t.name}</div>
            <div className="muted" style={{ fontSize: 13, marginTop: 4 }}>
              {(t.target_urls || []).join(', ') || 'no URLs'}{t.repo_path ? ` · ${t.repo_path}` : ''}
            </div>
            <div className="row" style={{ marginTop: 6 }}>
              {t.safe_mode && <span className="pill">safe</span>}
              {t.offline && <span className="pill">offline</span>}
              {t.ssrf_canary && <span className="pill">ssrf-canary</span>}
            </div>
          </div>
          <div className="row">
            <button onClick={() => runScan(t.id)} disabled={busy === t.id}>
              {busy === t.id ? 'Scanning…' : 'Run scan'}
            </button>
            <button className="danger" onClick={() => remove(t.id)}>Delete</button>
          </div>
        </div>
      ))}
    </>
  )
}
