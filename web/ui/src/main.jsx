import React from 'react'
import { createRoot } from 'react-dom/client'
import { BrowserRouter, Routes, Route, Link, useNavigate } from 'react-router-dom'
import axios from 'axios'

axios.defaults.baseURL = ''

function Login({ onLogin }) {
  const [username, setUsername] = React.useState('')
  const [password, setPassword] = React.useState('')
  const nav = useNavigate()
  const submit = async (e) => {
    e.preventDefault()
    try {
      const r = await axios.post('/api/v1/auth/login', { username, password })
      const token = r.data.token
      localStorage.setItem('token', token)
      axios.defaults.headers.common['Authorization'] = `Bearer ${token}`
      onLogin()
      nav('/admin')
    } catch (e) {
      alert('login failed')
    }
  }
  return (
    <form onSubmit={submit}>
      <h3>Login</h3>
      <input placeholder="username" value={username} onChange={e=>setUsername(e.target.value)} />
      <input placeholder="password" type="password" value={password} onChange={e=>setPassword(e.target.value)} />
      <button>Login</button>
    </form>
  )
}

function Admin() {
  return (
    <div>
      <h2>Admin Panel</h2>
      <nav>
        <Link to="/admin/servers">Servers</Link> | <Link to="/admin/zones">Zones</Link>
      </nav>
      <Routes>
        <Route path="/admin/servers" element={<Servers />} />
        <Route path="/admin/zones" element={<Zones />} />
      </Routes>
    </div>
  )
}

function User() {
  return (
    <div>
      <h2>User Panel</h2>
      <p>Manage your records and view stats (placeholder)</p>
    </div>
  )
}

function Servers() {
  const [servers, setServers] = React.useState([])
  const [name, setName] = React.useState('')
  const [addr, setAddr] = React.useState('')
  React.useEffect(() => {
    const token = localStorage.getItem('token')
    if (token) axios.defaults.headers.common['Authorization'] = `Bearer ${token}`
    axios.get('/api/v1/servers').then(r => setServers(r.data)).catch(()=>{})
  }, [])
  const create = async () => {
    await axios.post('/api/v1/servers', { name, address: addr })
    const r = await axios.get('/api/v1/servers')
    setServers(r.data)
  }
  return (
    <div>
      <h3>Servers</h3>
      <div>
        <input placeholder="name" value={name} onChange={e=>setName(e.target.value)} />
        <input placeholder="address" value={addr} onChange={e=>setAddr(e.target.value)} />
        <button onClick={create}>Create</button>
      </div>
      <pre>{JSON.stringify(servers, null, 2)}</pre>
    </div>
  )
}

function Zones() {
  const [zones, setZones] = React.useState([])
  React.useEffect(() => {
    axios.get('/api/v1/zones').then(r => setZones(r.data)).catch(()=>{})
  }, [])
  return (
    <div>
      <h3>Zones</h3>
      <pre>{JSON.stringify(zones, null, 2)}</pre>
    </div>
  )
}

function App() {
  const [authed, setAuthed] = React.useState(!!localStorage.getItem('token'))
  return (
    <BrowserRouter>
      <header>
        <h1>Hickory DNS Control</h1>
        <nav>
          <Link to="/admin">Admin</Link> | <Link to="/user">User</Link>
        </nav>
      </header>
      <Routes>
        <Route path="/login" element={<Login onLogin={() => setAuthed(true)} />} />
        <Route path="/admin/*" element={authed ? <Admin /> : <Login onLogin={() => setAuthed(true)} />} />
        <Route path="/user" element={<User />} />
        <Route path="/" element={<div>Welcome to Hickory DNS Control</div>} />
      </Routes>
    </BrowserRouter>
  )
}

createRoot(document.getElementById('root')).render(<App />)
