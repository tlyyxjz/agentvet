import { Routes, Route } from 'react-router-dom'
import Layout from './components/Layout'
import Landing from './pages/Landing'
import Dashboard from './pages/Dashboard'
import ScanResult from './pages/ScanResult'

export default function App() {
  return (
    <Routes>
      <Route path="/" element={<Landing />} />
      <Route element={<Layout />}>
        <Route path="/app" element={<Dashboard />} />
        <Route path="/app/scan/:id" element={<ScanResult />} />
      </Route>
    </Routes>
  )
}
