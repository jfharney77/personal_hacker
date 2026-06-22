import { useCallback, useEffect, useState } from 'react'
import { useParams, Link } from 'react-router-dom'
import { api, SEVERITIES } from '../api.js'

export default function ScanDetail() {
  const { id } = useParams()
  const [data, setData] = useState(null)
  const [err, setErr] = useState(null)

  const load = useCallback(() => {
    api.getScan(id).then(setData).catch((e) => setErr(e.message))
  }, [id])
  useEffect(() => { load() }, [load])

  if (err) return <p className="status-error">Error: {err}</p>
  if (!data) return <p className="muted">Loading…</p>

  const { scan, findings } = data

  async function toggle(f) {
    if (f.suppressed) await api.unsuppress(f.fingerprint)
    else {
      const reason = prompt('Reason for suppressing this finding (optional):') ?? ''
      await api.suppress(f.fingerprint, reason)
    }
    load()
  }

  const counts = { critical: scan.critical, high: scan.high, medium: scan.medium, low: scan.low, info: scan.info }

  return (
    <>
      <div className="spread">
        <h1 style={{ marginBottom: 0 }}>Scan #{scan.id}</h1>
        <Link to="/" className="muted">← dashboard</Link>
      </div>
      <p className={`status-${scan.status}`} style={{ marginTop: 6 }}>
        {scan.status}{scan.error ? ` — ${scan.error}` : ''} · {new Date(scan.started_at).toLocaleString()}
      </p>

      <div className="row" style={{ margin: '12px 0 20px' }}>
        {SEVERITIES.map((s) => (
          <span key={s} className="row" style={{ gap: 6 }}>
            <span className="sev-dot" style={{ background: `var(--${s})` }} />
            <span style={{ textTransform: 'capitalize' }}>{s}</span>
            <strong>{counts[s]}</strong>
          </span>
        ))}
        {scan.suppressed_count > 0 && <span className="pill">{scan.suppressed_count} suppressed</span>}
      </div>

      {findings.length === 0 && scan.status === 'done' && (
        <div className="panel"><span className="ok">No findings 🎉</span></div>
      )}

      {findings.map((f) => (
        <div className={`finding ${f.suppressed ? 'suppressed' : ''}`} key={f.id}>
          <div className="head">
            <span className={`badge ${f.severity}`}>{f.severity}</span>
            <span className="title">{f.title}</span>
            {f.cross_validated && <span className="pill">✅ cross-validated</span>}
            <span style={{ marginLeft: 'auto' }}>
              <button className="ghost" onClick={() => toggle(f)}>
                {f.suppressed ? 'Unsuppress' : 'Suppress'}
              </button>
            </span>
          </div>
          <div className="meta">
            {f.threat_class} · {f.method}{f.location ? <> · <code>{f.location}</code></> : null}
          </div>
          <div>{f.detail}</div>
          {f.evidence && <div className="meta">Evidence: <code>{f.evidence}</code></div>}
          {f.remediation && <div className="fix"><strong>Fix:</strong> {f.remediation}</div>}
          <div className="meta">fingerprint <code>{f.fingerprint}</code></div>
        </div>
      ))}
    </>
  )
}
