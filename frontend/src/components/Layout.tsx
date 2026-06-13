import { Link, Outlet, useLocation } from 'react-router-dom'

export default function Layout() {
  const { pathname } = useLocation()

  return (
    <div className="min-h-screen flex">
      {/* Sidebar */}
      <aside className="w-64 bg-gray-900 border-r border-gray-800 p-6 flex flex-col">
        <Link to="/" className="text-xl font-bold gradient-text mb-8">
          AgentVet
        </Link>

        <nav className="flex flex-col gap-2 flex-1">
          <NavItem to="/app" active={pathname === '/app'}>
            Dashboard
          </NavItem>
          <NavItem to="/app" active={pathname.startsWith('/app/scan')}>
            Scan History
          </NavItem>
        </nav>

        <div className="text-xs text-gray-600">
          v0.4.0 — Free tier (10 scans/mo)
        </div>
      </aside>

      {/* Main content */}
      <main className="flex-1 p-8 overflow-auto">
        <Outlet />
      </main>
    </div>
  )
}

function NavItem({
  to,
  active,
  children,
}: {
  to: string
  active: boolean
  children: React.ReactNode
}) {
  return (
    <Link
      to={to}
      className={`px-3 py-2 rounded-lg text-sm transition-colors ${
        active
          ? 'bg-blue-600/20 text-blue-400 font-medium'
          : 'text-gray-400 hover:text-gray-200 hover:bg-gray-800'
      }`}
    >
      {children}
    </Link>
  )
}
