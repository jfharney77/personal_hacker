import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { api, SEVERITIES } from '../api.js'

export default function Dashboard() {
  const [stats, setStats] = useState(null)
  const [scans, setScans] = useState([])
  const [targets, setTargets] = useState([])
  const [err, setErr] = useState(null)

  useEffect(() => {
    Promise.all([api.stats(), api.listScans(), api.listTargets()])
      .then(([s, sc, t]) => { setStats(s); setScans(sc); setTargets(t) })
      .catch((e) => setErr(e.message))
  }, [])

  if (err) return <p className="status-error">Error: {err}. Is the backend running?</p>
  if (!stats) return <p className="muted">Loading…</p>

  const nameOf = (id) => targets.find((t) => t.id === id)?.name || `#${id}`

  return (
    <>
      <h1>Dashboard</h1>
      <div className="cards">
        <div className="card"><div className="num">{stats.targets}</div><div className="label">Targets</div></div>
        <div className="card"><div className="num">{stats.scans}</div><div className="label">Scans run</div></div>
        <div className="card"><div className="num">{stats.open_total}</div><div className="label">Open findings (latest per target)</div></div>
      </div>

      <h2>Open findings by severity</h2>
      <div className="cards">
        {SEVERITIES.map((s) => (
          <div className="card" key={s}>
            <div className="num"><span className={`sev-dot`} style={{ background: `var(--${s})` }} />{stats.open_by_severity[s]}</div>
            <div className="label" style={{ textTransform: 'capitalize' }}>{s}</div>
          </div>
        ))}
      </div>

      <h2>Recent scans</h2>
      <div className="panel">
        {scans.length === 0 ? <p className="muted">No scans yet. Add a target and run one.</p> : (
          <table>
            <thead><tr><th>Target</th><th>Status</th><th>Findings</th><th>When</th><th></th></tr></thead>
            <tbody>
              {scans.map((s) => (
                <tr key={s.id}>
                  <td>{nameOf(s.target_id)}</td>
                  <td className={`status-${s.status}`}>{s.status}</td>
                  <td>{s.status === 'done' ? `${s.total} (${s.critical}C / ${s.high}H)` : '—'}</td>
                  <td className="muted">{new Date(s.started_at).toLocaleString()}</td>
                  <td><Link to={`/scans/${s.id}`}>view →</Link></td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </>
  )
}
