import { useEffect, useState } from 'react'
import { api } from '../api.js'

export default function Suppressions() {
  const [items, setItems] = useState([])
  const [err, setErr] = useState(null)

  const load = () => api.listSuppressions().then(setItems).catch((e) => setErr(e.message))
  useEffect(() => { load() }, [])

  async function remove(fp) {
    await api.unsuppress(fp)
    load()
  }

  return (
    <>
      <h1>Suppressions</h1>
      <p className="muted">
        Suppressed fingerprints are muted across all future scans (accepted risk / false
        positive). They're excluded from severity counts and CI gating.
      </p>
      <div className="panel">
        {err && <p className="status-error">{err}</p>}
        {items.length === 0 ? <p className="muted">Nothing suppressed.</p> : (
          <table>
            <thead><tr><th>Fingerprint</th><th>Reason</th><th>Since</th><th></th></tr></thead>
            <tbody>
              {items.map((s) => (
                <tr key={s.fingerprint}>
                  <td><code>{s.fingerprint}</code></td>
                  <td>{s.reason || <span className="muted">—</span>}</td>
                  <td className="muted">{new Date(s.created_at).toLocaleString()}</td>
                  <td><button className="ghost" onClick={() => remove(s.fingerprint)}>Remove</button></td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </>
  )
}
