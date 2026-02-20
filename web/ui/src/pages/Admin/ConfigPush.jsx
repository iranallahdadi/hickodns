import React from 'react'
import api from '../../api/client'

export default function ConfigPush(){
  const [agentId, setAgentId] = React.useState('')
  const [zoneId, setZoneId] = React.useState('')
  const [result, setResult] = React.useState(null)

  React.useEffect(() => {
    const token = localStorage.getItem('token')
    if (token) api.setToken(token)
  }, [])

  const push = async () => {
    try { const r = await api.post('/api/v1/config/push', { agent_id: agentId, zone_id: zoneId, zone_config: {} }); setResult(r.data) } catch (e) { alert('Error pushing config') }
  }

  return (
    <div className="bg-white shadow rounded p-6">
      <h3 className="text-lg font-semibold mb-3">Push Config to Agent</h3>
      <div className="grid gap-2 max-w-md mb-4">
        <input className="border rounded px-3 py-2" placeholder="agent ID" value={agentId} onChange={e=>setAgentId(e.target.value)} />
        <input className="border rounded px-3 py-2" placeholder="zone ID" value={zoneId} onChange={e=>setZoneId(e.target.value)} />
        <button className="bg-blue-600 text-white px-4 py-2 rounded" onClick={push}>Push Config</button>
      </div>
      {result && <pre className="bg-gray-100 p-3 rounded">{JSON.stringify(result, null, 2)}</pre>}
    </div>
  )
}
