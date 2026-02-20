import { create } from 'zustand';
import { persist } from 'zustand/middleware';
import { setAuthToken, authApi } from '../api/client';
import api from '../api/client';

export const useAuthStore = create(
  persist(
    (set, get) => ({
      user: null,
      token: null,
      isAuthenticated: false,
      isLoading: false,
      error: null,
      
      login: async (username, password) => {
        set({ isLoading: true, error: null });
        try {
          const response = await authApi.login({ username, password });
          const { token } = response.data;
          setAuthToken(token);
          const meResponse = await api.get('/api/v1/auth/me');
          const user = meResponse.data;
          
          // Store user in localStorage for persistence
          localStorage.setItem('token', token);
          localStorage.setItem('user', JSON.stringify(user));
          
          set({ user, token, isAuthenticated: true, isLoading: false });
          return user;
        } catch (error) {
          const message = error.response?.data?.error || 'Login failed';
          set({ error: message, isLoading: false, isAuthenticated: false });
          throw new Error(message);
        }
      },
      
      logout: () => {
        setAuthToken(null);
        set({ user: null, token: null, isAuthenticated: false });
      },
      
      clearError: () => set({ error: null }),
      
      setUser: (user) => set({ user }),
      
      isAdmin: () => get().user?.role === 'admin',
      
      isAgent: () => get().user?.role === 'agent',
      
      // Initialize auth state from persisted token
      initializeAuth: () => {
        const state = get();
        if (state.token && !state.isAuthenticated) {
          const token = localStorage.getItem('token');
          const user = localStorage.getItem('user');
          if (token) {
            setAuthToken(token);
            set({ 
              token, 
              user: user ? JSON.parse(user) : null, 
              isAuthenticated: true 
            });
          }
        }
      }
    }),
    {
      name: 'auth-storage',
      partialize: (state) => ({ 
        token: state.token, 
        user: state.user,
        isAuthenticated: state.isAuthenticated 
      }),
    }
  )
);

// Zones Store
export const useZonesStore = create((set, get) => ({
  zones: [],
  selectedZone: null,
  isLoading: false,
  error: null,
  
  setZones: (zones) => set({ zones }),
  setSelectedZone: (zone) => set({ selectedZone: zone }),
  
  addZone: (zone) => set((state) => ({ 
    zones: [...state.zones, zone] 
  })),
  
  updateZone: (id, data) => set((state) => ({
    zones: state.zones.map(z => z.id === id ? { ...z, ...data } : z)
  })),
  
  removeZone: (id) => set((state) => ({
    zones: state.zones.filter(z => z.id !== id)
  })),
  
  setLoading: (isLoading) => set({ isLoading }),
  setError: (error) => set({ error }),
}));

// UI Store
export const useUIStore = create((set) => ({
  sidebarOpen: true,
  theme: 'light',
  notifications: [],
  
  toggleSidebar: () => set((state) => ({ sidebarOpen: !state.sidebarOpen })),
  setTheme: (theme) => set({ theme }),
  
  addNotification: (notification) => set((state) => ({
    notifications: [...state.notifications, { 
      id: Date.now(), 
      ...notification 
    }]
  })),
  
  removeNotification: (id) => set((state) => ({
    notifications: state.notifications.filter(n => n.id !== id)
  })),
  
  clearNotifications: () => set({ notifications: [] }),
}));
