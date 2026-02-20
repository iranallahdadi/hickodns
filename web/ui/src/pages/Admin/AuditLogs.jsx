import React from 'react'
import api from '../../api/client'

export default function AuditLogs(){
  const [logs, setLogs] = React.useState([])
  const [q, setQ] = React.useState('')

  const load = async ()=>{ try { const r = await api.get('/api/v1/audit/logs'); setLogs(r.data||[]) } catch(e){ console.error(e) } }
  React.useEffect(()=>{ const t=localStorage.getItem('token'); if(t) api.setToken(t); load() }, [])

  const exportCSV = ()=>{
    const hdrs = ['time','actor','action','details']
    const rows = logs.map(l => [l.time, l.actor, l.action, JSON.stringify(l.details)])
    const csv = [hdrs.join(','), ...rows.map(r=> r.map(c=>`"${String(c).replace(/"/g,'""')}"`).join(','))].join('\n')
    const blob = new Blob([csv], { type: 'text/csv' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url; a.download = 'audit_logs.csv'; a.click(); URL.revokeObjectURL(url)
  }

  const filtered = logs.filter(l=> JSON.stringify(l).toLowerCase().includes(q.toLowerCase()))

  return (
    <div className="bg-white shadow rounded p-6">
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-lg font-semibold">Audit Logs</h3>
        <div className="flex items-center space-x-2">
          <input className="border rounded px-3 py-2" placeholder="Filter logs..." value={q} onChange={e=>setQ(e.target.value)} />
          <button className="bg-gray-200 px-3 py-1 rounded" onClick={exportCSV}>Export CSV</button>
        </div>
      </div>
      <div className="overflow-auto max-h-96">
        <table className="w-full table-auto border-collapse text-sm">
          <thead><tr className="bg-gray-50"><th className="border px-2 py-1">Time</th><th className="border px-2 py-1">Actor</th><th className="border px-2 py-1">Action</th><th className="border px-2 py-1">Details</th></tr></thead>
          <tbody>
            {filtered.map((l,i)=> (
              <tr key={i}><td className="border px-2 py-1">{l.time}</td><td className="border px-2 py-1">{l.actor}</td><td className="border px-2 py-1">{l.action}</td><td className="border px-2 py-1">{JSON.stringify(l.details)}</td></tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
