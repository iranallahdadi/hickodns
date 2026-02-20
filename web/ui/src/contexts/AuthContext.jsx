import React from 'react'
import api from '../api/client'

const AuthContext = React.createContext()

export function AuthProvider({ children }){
  const [user, setUser] = React.useState(null)
  const [loading, setLoading] = React.useState(true)

  React.useEffect(()=>{
    const load = async ()=>{
      const token = localStorage.getItem('token')
      if (token) api.setToken(token)
      try {
        if (token){
          const r = await api.get('/api/v1/auth/me')
          setUser(r.data)
        }
      } catch (e) {
        console.warn('auth fetch failed', e)
        localStorage.removeItem('token')
        api.setToken(null)
      }
      setLoading(false)
    }
    load()
  }, [])

  const login = async (username, password) => {
    const r = await api.post('/api/v1/auth/login', { username, password })
    const token = r.data.token
    localStorage.setItem('token', token)
    api.setToken(token)
    const me = await api.get('/api/v1/auth/me')
    setUser(me.data)
    return me.data
  }

  const logout = ()=>{
    localStorage.removeItem('token')
    api.setToken(null)
    setUser(null)
  }

  return <AuthContext.Provider value={{ user, loading, login, logout }}>{children}</AuthContext.Provider>
}

export default AuthContext
