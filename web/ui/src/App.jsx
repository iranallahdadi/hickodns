import React from 'react';
import { Routes, Route, Navigate } from 'react-router-dom';
import Layout from './components/Layout';
import Login from './pages/Login';
import AdminDashboard from './pages/Admin/Dashboard';
import AdminZones from './pages/Admin/Zones';
import AdminUsers from './pages/Admin/Users';
import AdminServers from './pages/Admin/Servers';
import AdminAgents from './pages/Admin/Agents';
import AdminGeoRules from './pages/Admin/GeoRules';
import AdminConfigPush from './pages/Admin/ConfigPush';
import AdminAuditLogs from './pages/Admin/AuditLogs';
import Records from './pages/Records';
import UserDashboard from './pages/User';
import { useAuthStore } from './store';

function ProtectedRoute({ children, requireAdmin = false }) {
  const { isAuthenticated, user } = useAuthStore();
  
  if (!isAuthenticated) {
    return <Navigate to="/login" replace />;
  }
  
  if (requireAdmin && user?.role !== 'admin') {
    return <Navigate to="/user" replace />;
  }
  
  return children;
}

function AdminRoutes() {
  return (
    <Routes>
      <Route path="/" element={<AdminDashboard />} />
      <Route path="/zones" element={<AdminZones />} />
      <Route path="/zones/:id/records" element={<Records />} />
      <Route path="/users" element={<AdminUsers />} />
      <Route path="/servers" element={<AdminServers />} />
      <Route path="/agents" element={<AdminAgents />} />
      <Route path="/georules" element={<AdminGeoRules />} />
      <Route path="/metrics" element={<AdminDashboard />} />
      <Route path="/audit" element={<AdminAuditLogs />} />
      <Route path="/certificates" element={<AdminDashboard />} />
      <Route path="/config" element={<AdminConfigPush />} />
    </Routes>
  );
}

function UserRoutes() {
  return (
    <Routes>
      <Route path="/" element={<UserDashboard />} />
    </Routes>
  );
}

export default function App() {
  const { isAuthenticated, user } = useAuthStore();
  
  // Redirect authenticated users to their dashboard
  if (isAuthenticated && window.location.pathname === '/login') {
    return <Navigate to={user?.role === 'admin' ? '/admin' : '/user'} replace />;
  }
  
  return (
    <Layout>
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route 
          path="/admin/*" 
          element={
            <ProtectedRoute requireAdmin>
              <AdminRoutes />
            </ProtectedRoute>
          } 
        />
        <Route 
          path="/user/*" 
          element={
            <ProtectedRoute>
              <UserRoutes />
            </ProtectedRoute>
          } 
        />
        <Route 
          path="/" 
          element={
            isAuthenticated 
              ? <Navigate to={user?.role === 'admin' ? '/admin' : '/user'} replace />
              : <Navigate to="/login" replace />
          } 
        />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </Layout>
  );
}
