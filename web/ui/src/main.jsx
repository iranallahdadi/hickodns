import React from 'react';
import { createRoot } from 'react-dom/client';
import { BrowserRouter } from 'react-router-dom';
import App from './App';
import { setAuthToken } from './api/client';
import { useAuthStore } from './store';
import { NotificationsProvider } from './components/Notifications';
import './index.css';

// Initialize auth state from localStorage on app load
const initializeAuth = () => {
  const token = localStorage.getItem('token');
  const userStr = localStorage.getItem('user');
  
  if (token) {
    setAuthToken(token);
    const user = userStr ? JSON.parse(userStr) : null;
    useAuthStore.setState({ token, user, isAuthenticated: true });
  }
};

// Run initialization
initializeAuth();

const container = document.getElementById('root');
const root = createRoot(container);

root.render(
  <React.StrictMode>
    <BrowserRouter>
      <NotificationsProvider>
        <App />
      </NotificationsProvider>
    </BrowserRouter>
  </React.StrictMode>
);
