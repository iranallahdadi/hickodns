import React from 'react'
import { createRoot } from 'react-dom/client'
import { BrowserRouter, Routes, Route, Link, useNavigate } from 'react-router-dom'
import axios from 'axios'

axios.defaults.baseURL = 'http://localhost:8080'

const styles = {
  container: { maxWidth: '1200px', margin: '0 auto', padding: '20px', fontFamily: 'Arial, sans-serif' },
  header: { borderBottom: '2px solid #333', paddingBottom: '10px', marginBottom: '20px' },
  nav: { marginTop: '10px' },
  form: { display: 'grid', gap: '10px', maxWidth: '400px', marginBottom: '20px' },
  input: { padding: '8px', border: '1px solid #ccc', borderRadius: '4px' },
  button: { padding: '8px 16px', backgroundColor: '#007bff', color: 'white', border: 'none', borderRadius: '4px', cursor: 'pointer' },
  table: { width: '100%', borderCollapse: 'collapse', marginTop: '20px' },
  td: { border: '1px solid #ddd', padding: '8px' },
  error: { color: 'red', marginTop: '10px' },
  success: { color: 'green', marginTop: '10px' },
}

function Login({ onLogin }) {
  const [username, setUsername] = React.useState('')
  const [password, setPassword] = React.useState('')
  const [error, setError] = React.useState('')
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
      setError('Login failed')
    }
  }
  return (
    <div style={styles.container}>
      <h2>Hickory DNS Control - Login</h2>
      <form onSubmit={submit} style={styles.form}>
        <input style={styles.input} placeholder="username" value={username} onChange={e=>setUsername(e.target.value)} />
        <input style={styles.input} placeholder="password" type="password" value={password} onChange={e=>setPassword(e.target.value)} />
        <button style={styles.button}>Login</button>
      </form>
      {error && <p style={styles.error}>{error}</p>}
    </div>
  )
}

function Admin() {
  return (
    <div>
      <nav style={styles.nav}>
        <Link to="/admin/servers">Servers</Link> | 
        <Link to="/admin/zones"> Zones</Link> | 
        <Link to="/admin/georules"> GeoRules</Link> | 
        <Link to="/admin/config"> Config Push</Link>
      </nav>
      <Routes>
        <Route path="/servers" element={<Servers />} />
        <Route path="/zones" element={<Zones />} />
        <Route path="/georules" element={<GeoRules />} />
        <Route path="/config" element={<ConfigPush />} />
      </Routes>
    </div>
  )
}

function User() {
  return (
    <div style={styles.container}>
      <h2>User Panel</h2>
      <p>View your DNS zones and manage records</p>
      <Zones />
    </div>
  )
}

function Servers() {
  const [servers, setServers] = React.useState([])
  const [name, setName] = React.useState('')
  const [addr, setAddr] = React.useState('')
  const [region, setRegion] = React.useState('')
  const [loading, setLoading] = React.useState(false)
  const [success, setSuccess] = React.useState('')
  
  const load = async () => {
    try {
      const r = await axios.get('/api/v1/servers')
      setServers(r.data || [])
    } catch (e) {
      console.error('Error loading servers', e)
    }
  }
  
  React.useEffect(() => {
    const token = localStorage.getItem('token')
    if (token) axios.defaults.headers.common['Authorization'] = `Bearer ${token}`
    load()
  }, [])
  
  const create = async () => {
    try {
      setLoading(true)
      await axios.post('/api/v1/servers', { name, address: addr, region: region || null })
      setSuccess('Server created')
      setName('')
      setAddr('')
      setRegion('')
      load()
    } catch (e) {
      alert('Error creating server')
    } finally {
      setLoading(false)
    }
  }
  
  return (
    <div style={styles.container}>
      <h3>Servers</h3>
      <div style={styles.form}>
        <input style={styles.input} placeholder="name" value={name} onChange={e=>setName(e.target.value)} />
        <input style={styles.input} placeholder="address" value={addr} onChange={e=>setAddr(e.target.value)} />
        <input style={styles.input} placeholder="region (optional)" value={region} onChange={e=>setRegion(e.target.value)} />
        <button style={styles.button} onClick={create} disabled={loading}>Create Server</button>
      </div>
      {success && <p style={styles.success}>{success}</p>}
      <table style={styles.table}>
        <thead>
          <tr>
            <th style={styles.td}>ID</th>
            <th style={styles.td}>Name</th>
            <th style={styles.td}>Address</th>
            <th style={styles.td}>Region</th>
          </tr>
        </thead>
        <tbody>
          {servers.map(s => (
            <tr key={s.id}>
              <td style={styles.td}>{s.id}</td>
              <td style={styles.td}>{s.name}</td>
              <td style={styles.td}>{s.address}</td>
              <td style={styles.td}>{s.region || '-'}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function Zones() {
  const [zones, setZones] = React.useState([])
  const [domain, setDomain] = React.useState('')
  const [loading, setLoading] = React.useState(false)
  const [success, setSuccess] = React.useState('')
  
  const load = async () => {
    try {
      const r = await axios.get('/api/v1/zones')
      setZones(r.data || [])
    } catch (e) {
      console.error('Error loading zones', e)
    }
  }
  
  React.useEffect(() => {
    load()
  }, [])
  
  const create = async () => {
    try {
      setLoading(true)
      await axios.post('/api/v1/zones', { domain })
      setSuccess('Zone created')
      setDomain('')
      load()
    } catch (e) {
      alert('Error creating zone')
    } finally {
      setLoading(false)
    }
  }
  
  return (
    <div style={styles.container}>
      <h3>Zones</h3>
      <div style={styles.form}>
        <input style={styles.input} placeholder="domain" value={domain} onChange={e=>setDomain(e.target.value)} />
        <button style={styles.button} onClick={create} disabled={loading}>Create Zone</button>
      </div>
      {success && <p style={styles.success}>{success}</p>}
      <table style={styles.table}>
        <thead>
          <tr>
            <th style={styles.td}>ID</th>
            <th style={styles.td}>Domain</th>
          </tr>
        </thead>
        <tbody>
          {zones.map(z => (
            <tr key={z.id}>
              <td style={styles.td}>{z.id}</td>
              <td style={styles.td}>{z.domain}</td>
              <td style={styles.td}><Link to={`/admin/zones/${z.id}/records`}>Manage Records</Link></td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function Records() {
  const { pathname } = window.location
  const parts = pathname.split('/')
  const zoneId = parts[3]
  const [records, setRecords] = React.useState([])
  const [name, setName] = React.useState('')
  const [type, setType] = React.useState('A')
  const [value, setValue] = React.useState('')
  const [ttl, setTtl] = React.useState(3600)

  const load = async () => {
    try {
      const r = await axios.get(`/api/v1/zones/${zoneId}/records`)
      setRecords(r.data || [])
    } catch (e) {
      console.error('load records', e)
    }
  }

  React.useEffect(() => { load() }, [])

  const create = async () => {
    try {
      await axios.post(`/api/v1/zones/${zoneId}/records`, { name, record_type: type, value, ttl })
      setName(''); setValue(''); setTtl(3600)
      load()
    } catch (e) { alert('create failed') }
  }

  const remove = async (rid) => {
    try { await axios.delete(`/api/v1/zones/${zoneId}/records/${rid}`); load() } catch (e) { alert('delete failed') }
  }

  return (
    <div style={styles.container}>
      <h3>Records for zone {zoneId}</h3>
      <div style={styles.form}>
        <input style={styles.input} placeholder="name" value={name} onChange={e=>setName(e.target.value)} />
        <input style={styles.input} placeholder="type" value={type} onChange={e=>setType(e.target.value)} />
        <input style={styles.input} placeholder="value" value={value} onChange={e=>setValue(e.target.value)} />
        <input style={styles.input} placeholder="ttl" value={ttl} onChange={e=>setTtl(Number(e.target.value))} />
        <button style={styles.button} onClick={create}>Create Record</button>
      </div>
      <table style={styles.table}>
        <thead>
          <tr><th style={styles.td}>ID</th><th style={styles.td}>Name</th><th style={styles.td}>Type</th><th style={styles.td}>Value</th><th style={styles.td}>TTL</th><th style={styles.td}>Actions</th></tr>
        </thead>
        <tbody>
          {records.map(r => (
            <tr key={r.id}>
              <td style={styles.td}>{r.id}</td>
              <td style={styles.td}>{r.name}</td>
              <td style={styles.td}>{r.record_type}</td>
              <td style={styles.td}>{r.value}</td>
              <td style={styles.td}>{r.ttl}</td>
              <td style={styles.td}><button style={styles.button} onClick={()=>remove(r.id)}>Delete</button></td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function GeoRules() {
  const [rules, setRules] = React.useState([])
  const [zone, setZone] = React.useState('')
  const [matchType, setMatchType] = React.useState('country')
  const [matchValue, setMatchValue] = React.useState('US')
  const [target, setTarget] = React.useState('192.0.2.1')
  const [loading, setLoading] = React.useState(false)
  const [success, setSuccess] = React.useState('')
  const [testIp, setTestIp] = React.useState('8.8.8.8')
  const [resolveResult, setResolveResult] = React.useState(null)
  
  const load = async () => {
    try {
      const r = await axios.get('/api/v1/georules')
      setRules(r.data || [])
    } catch (e) {
      console.error('Error loading rules', e)
    }
  }
  
  React.useEffect(() => {
    load()
  }, [])
  
  const create = async () => {
    try {
      setLoading(true)
      await axios.post('/api/v1/georules', { zone_id: zone, match_type: matchType, match_value: matchValue, target })
      setSuccess('Rule created')
      setZone('')
      load()
    } catch (e) {
      alert('Error creating rule')
    } finally {
      setLoading(false)
    }
  }
  
  const testResolve = async () => {
    try {
      if (!zone) {
        alert('Select a zone')
        return
      }
      const r = await axios.post('/api/v1/georules/resolve', { zone_id: zone, client_ip: testIp })
      setResolveResult(r.data)
    } catch (e) {
      alert('Error resolving')
    }
  }
  
  return (
    <div style={styles.container}>
      <h3>GeoDNS Rules</h3>
      <div style={styles.form}>
        <input style={styles.input} placeholder="zone id" value={zone} onChange={e=>setZone(e.target.value)} />
        <select style={styles.input} value={matchType} onChange={e=>setMatchType(e.target.value)}>
          <option value="country">Country</option>
          <option value="region">Region</option>
          <option value="continent">Continent</option>
        </select>
        <input style={styles.input} placeholder="match value (e.g., US)" value={matchValue} onChange={e=>setMatchValue(e.target.value)} />
        <input style={styles.input} placeholder="target IP" value={target} onChange={e=>setTarget(e.target.value)} />
        <button style={styles.button} onClick={create} disabled={loading}>Create Rule</button>
      </div>
      {success && <p style={styles.success}>{success}</p>}
      
      <h4>Test Rule</h4>
      <div style={styles.form}>
        <input style={styles.input} placeholder="client IP" value={testIp} onChange={e=>setTestIp(e.target.value)} />
        <button style={styles.button} onClick={testResolve}>Resolve</button>
      </div>
      {resolveResult && <pre>{JSON.stringify(resolveResult, null, 2)}</pre>}
      
      <table style={styles.table}>
        <thead>
          <tr>
            <th style={styles.td}>ID</th>
            <th style={styles.td}>Zone</th>
            <th style={styles.td}>Type</th>
            <th style={styles.td}>Value</th>
            <th style={styles.td}>Target</th>
          </tr>
        </thead>
        <tbody>
          {rules.map(r => (
            <tr key={r.id}>
              <td style={styles.td}>{r.id}</td>
              <td style={styles.td}>{r.zone_id}</td>
              <td style={styles.td}>{r.match_type}</td>
              <td style={styles.td}>{r.match_value}</td>
              <td style={styles.td}>{r.target}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function ConfigPush() {
  const [agentId, setAgentId] = React.useState('')
  const [zoneId, setZoneId] = React.useState('')
  const [loading, setLoading] = React.useState(false)
  const [result, setResult] = React.useState(null)
  
  const push = async () => {
    try {
      setLoading(true)
      const r = await axios.post('/api/v1/config/push', {
        agent_id: agentId,
        zone_id: zoneId,
        zone_config: { /* config would be built from zone data */ }
      })
      setResult(r.data)
    } catch (e) {
      alert('Error pushing config')
    } finally {
      setLoading(false)
    }
  }
  
  return (
    <div style={styles.container}>
      <h3>Push Config to Agent</h3>
      <div style={styles.form}>
        <input style={styles.input} placeholder="agent ID" value={agentId} onChange={e=>setAgentId(e.target.value)} />
        <input style={styles.input} placeholder="zone ID" value={zoneId} onChange={e=>setZoneId(e.target.value)} />
        <button style={styles.button} onClick={push} disabled={loading}>Push Config</button>
      </div>
      {result && <pre>{JSON.stringify(result, null, 2)}</pre>}
    </div>
  )
}

function App() {
  const [authed, setAuthed] = React.useState(!!localStorage.getItem('token'))
  const nav = useNavigate()
  
  const logout = () => {
    localStorage.removeItem('token')
    delete axios.defaults.headers.common['Authorization']
    setAuthed(false)
    nav('/')
  }
  
  return (
    <div>
      <header style={styles.header}>
        <h1>🌐 Hickory DNS Control</h1>
        <nav style={styles.nav}>
          {authed && (
            <>
              <Link to="/admin">Admin</Link> | 
              <Link to="/user"> User</Link> | 
              <button onClick={logout} style={{...styles.button, padding: '4px 12px', marginLeft: '10px'}}>Logout</button>
            </>
          )}
        </nav>
      </header>
      <Routes>
        <Route path="/login" element={<Login onLogin={() => setAuthed(true)} />} />
        <Route path="/admin/*" element={authed ? <Admin /> : <Login onLogin={() => setAuthed(true)} />} />
        <Route path="/admin/zones/:id/records" element={authed ? <Records /> : <Login onLogin={() => setAuthed(true)} />} />
        <Route path="/user" element={authed ? <User /> : <Login onLogin={() => setAuthed(true)} />} />
        <Route path="/" element={
          <div style={styles.container}>
            <h2>Welcome to Hickory DNS Control</h2>
            {!authed && <Link to="/login">Click here to login</Link>}
          </div>
        } />
      </Routes>
    </div>
  )
}

createRoot(document.getElementById('root')).render(
  <BrowserRouter>
    <App />
  </BrowserRouter>
)
