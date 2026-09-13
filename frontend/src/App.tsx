import { BrowserRouter, Navigate, Route, Routes } from "react-router-dom";
import { AuthProvider } from "@/hooks/useAuth";
import { ProtectedRoute } from "@/components/ProtectedRoute";
import { AppShell } from "@/components/AppShell";
import LoginPage from "@/pages/LoginPage";
import SocOverviewPage from "@/pages/SocOverviewPage";
import AlertsPage from "@/pages/AlertsPage";
import AlertDetailPage from "@/pages/AlertDetailPage";
import IncidentsPage from "@/pages/IncidentsPage";
import IncidentDetailPage from "@/pages/IncidentDetailPage";
import EventExplorerPage from "@/pages/EventExplorerPage";
import ThreatHuntingPage from "@/pages/ThreatHuntingPage";
import MitrePage from "@/pages/MitrePage";
import ThreatIntelPage from "@/pages/ThreatIntelPage";
import AssetsPage from "@/pages/AssetsPage";
import UsersPage from "@/pages/UsersPage";
import RulesPage from "@/pages/RulesPage";
import PlaybooksPage from "@/pages/PlaybooksPage";
import ReportsPage from "@/pages/ReportsPage";
import AuditPage from "@/pages/AuditPage";
import AdministrationPage from "@/pages/AdministrationPage";

export default function App() {
  return (
    <BrowserRouter>
      <AuthProvider>
        <Routes>
          <Route path="/login" element={<LoginPage />} />
          <Route
            element={
              <ProtectedRoute>
                <AppShell />
              </ProtectedRoute>
            }
          >
            <Route index element={<SocOverviewPage />} />
            <Route path="alerts" element={<AlertsPage />} />
            <Route path="alerts/:alertId" element={<AlertDetailPage />} />
            <Route path="incidents" element={<IncidentsPage />} />
            <Route path="incidents/:incidentId" element={<IncidentDetailPage />} />
            <Route path="events" element={<EventExplorerPage />} />
            <Route path="hunting" element={<ThreatHuntingPage />} />
            <Route path="mitre" element={<MitrePage />} />
            <Route path="threat-intel" element={<ThreatIntelPage />} />
            <Route path="assets" element={<AssetsPage />} />
            <Route path="users" element={<UsersPage />} />
            <Route path="rules" element={<RulesPage />} />
            <Route path="playbooks" element={<PlaybooksPage />} />
            <Route path="reports" element={<ReportsPage />} />
            <Route path="audit" element={<AuditPage />} />
            <Route path="administration" element={<AdministrationPage />} />
          </Route>
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </AuthProvider>
    </BrowserRouter>
  );
}
