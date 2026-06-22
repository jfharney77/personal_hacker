import { NavLink, Route, Routes } from 'react-router-dom'
import Dashboard from './pages/Dashboard.jsx'
import Targets from './pages/Targets.jsx'
import ScanDetail from './pages/ScanDetail.jsx'
import Suppressions from './pages/Suppressions.jsx'

export default function App() {
  return (
    <>
      <nav className="nav">
        <div className="brand">personal<span>_hacker</span></div>
        <NavLink to="/" end>Dashboard</NavLink>
        <NavLink to="/targets">Targets</NavLink>
        <NavLink to="/suppressions">Suppressions</NavLink>
      </nav>
      <div className="container">
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/targets" element={<Targets />} />
          <Route path="/scans/:id" element={<ScanDetail />} />
          <Route path="/suppressions" element={<Suppressions />} />
        </Routes>
      </div>
    </>
  )
}
