import { Navigate, Route, Routes } from 'react-router-dom'
import { Center, Loader } from '@mantine/core'
import { AuthProvider, useAuth } from './lib/auth'
import { AppLayout } from './components/AppLayout'
import LoginPage from './pages/LoginPage'
import OverviewPage from './pages/OverviewPage'
import InboundsPage from './pages/InboundsPage'
import UsersPage from './pages/UsersPage'
import ForwardsPage from './pages/ForwardsPage'
import SettingsPage from './pages/SettingsPage'
import LogsPage from './pages/LogsPage'
import IngressesPage from './pages/IngressesPage'
import RoutingPage from './pages/RoutingPage'
import CertificatesPage from './pages/CertificatesPage'
import ProbePage from './pages/ProbePage'

function Protected({ children }: { children: React.ReactNode }) {
  const { me, loading } = useAuth()
  if (loading) return <Center h="100vh"><Loader /></Center>
  if (!me) return <Navigate to="/login" replace />
  return <>{children}</>
}

export default function App() {
  return (
    <AuthProvider>
      <Routes>
        <Route path="/login" element={<LoginPage />} />
        <Route element={<Protected><AppLayout /></Protected>}>
          <Route path="/" element={<OverviewPage />} />
          <Route path="/inbounds" element={<InboundsPage />} />
          <Route path="/users" element={<UsersPage />} />
          <Route path="/forwards" element={<ForwardsPage />} />
          <Route path="/ingresses" element={<IngressesPage />} />
          <Route path="/routing" element={<RoutingPage />} />
          <Route path="/certificates" element={<CertificatesPage />} />
          <Route path="/probe" element={<ProbePage />} />
          <Route path="/settings" element={<SettingsPage />} />
          <Route path="/logs" element={<LogsPage />} />
        </Route>
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </AuthProvider>
  )
}
