import React from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import api from '../api/client'
import BulkImport from '../components/BulkImport'
import Notifications from '../components/Notifications'
import { useParams } from 'react-router-dom'
import { FileText, Plus, Trash2, Download, RefreshCw } from 'lucide-react'

export default function Records(){
  const { id } = useParams()
  const zoneId = id
  const [records, setRecords] = React.useState([])
  const [name, setName] = React.useState('')
  const [type, setType] = React.useState('A')
  const [value, setValue] = React.useState('')
  const [ttl, setTtl] = React.useState(3600)
  const [error, setError] = React.useState('')
  const [loading, setLoading] = React.useState(false)
  const notify = React.useContext(Notifications)

  const load = async () => { 
    setLoading(true)
    try { 
      const r = await api.get(`/api/v1/zones/${zoneId}/records`); 
      setRecords(r.data || []) 
    } catch (e) { console.error('load records', e) }
    setLoading(false)
  }
  React.useEffect(()=>{ 
    const token = localStorage.getItem('token')
    if (token) api.setToken(token)
    load() 
  }, [zoneId])

  const create = async () => {
    setError('')
    if (!type || !value) { setError('Type and value are required'); return }
    try { 
      await api.post(`/api/v1/zones/${zoneId}/records`, { name, record_type: type, value, ttl }); 
      setName(''); setValue(''); setTtl(3600); 
      load(); 
      notify && notify.push('Record created successfully') 
    } catch (e) { setError('create failed') } 
  }
  
  const remove = async (rid) => { 
    try { 
      await api.delete(`/api/v1/zones/${zoneId}/records/${rid}`); 
      load() 
    } catch (e) { alert('delete failed') } 
  }
  
  const onBulkComplete = ()=> load()

  const downloadTemplate = () => {
    const sample = 'name,record_type,value,ttl\nwww,A,192.0.2.1,3600\nmail,A,192.0.2.2,3600\n@,MX,mail.example.com.,3600\n'
    const blob = new Blob([sample], { type: 'text/csv' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = 'records_template.csv'
    a.click()
    URL.revokeObjectURL(url)
  }

  const recordTypes = ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'SRV', 'NS', 'PTR', 'SOA', 'CAA']

  return (
    <div className="space-y-6">
      <motion.div 
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        className="bg-white shadow-lg rounded-xl p-6 border border-gray-100"
      >
        <div className="flex items-center justify-between mb-6">
          <div className="flex items-center space-x-3">
            <div className="p-2 bg-orange-100 rounded-lg">
              <FileText className="w-6 h-6 text-orange-600" />
            </div>
            <div>
              <h3 className="text-xl font-bold text-gray-800">DNS Records</h3>
              <p className="text-sm text-gray-500">Zone: {zoneId?.substring(0,8)}...</p>
            </div>
          </div>
          <button 
            onClick={load}
            className="p-2 hover:bg-gray-100 rounded-lg transition-colors"
          >
            <RefreshCw className={`w-5 h-5 text-gray-600 ${loading ? 'animate-spin' : ''}`} />
          </button>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Name</label>
            <input 
              className="w-full border border-gray-300 rounded-lg px-4 py-2 focus:ring-2 focus:ring-orange-500 focus:border-transparent" 
              placeholder="e.g., www" 
              value={name} 
              onChange={e=>setName(e.target.value)} 
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Type</label>
            <select 
              className="w-full border border-gray-300 rounded-lg px-4 py-2 focus:ring-2 focus:ring-orange-500 focus:border-transparent" 
              value={type} 
              onChange={e=>setType(e.target.value)}
            >
              {recordTypes.map(t => <option key={t} value={t}>{t}</option>)}
            </select>
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Value</label>
            <input 
              className="w-full border border-gray-300 rounded-lg px-4 py-2 focus:ring-2 focus:ring-orange-500 focus:border-transparent" 
              placeholder="e.g., 192.0.2.1" 
              value={value} 
              onChange={e=>setValue(e.target.value)} 
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">TTL</label>
            <input 
              type="number"
              className="w-full border border-gray-300 rounded-lg px-4 py-2 focus:ring-2 focus:ring-orange-500 focus:border-transparent" 
              placeholder="3600" 
              value={ttl} 
              onChange={e=>setTtl(Number(e.target.value))} 
            />
          </div>
          <div className="flex items-end">
            <button 
              className="w-full bg-gradient-to-r from-orange-500 to-orange-600 text-white px-4 py-2 rounded-lg hover:from-orange-600 hover:to-orange-700 transition-all flex items-center justify-center space-x-2 font-medium"
              onClick={create}
            >
              <Plus className="w-5 h-5" />
              <span>Add Record</span>
            </button>
          </div>
        </div>

        {error && (
          <motion.div 
            initial={{ opacity: 0, y: -10 }}
            animate={{ opacity: 1, y: 0 }}
            className="mt-4 bg-red-50 text-red-600 px-4 py-2 rounded-lg text-sm"
          >
            {error}
          </motion.div>
        )}

        <div className="flex items-center space-x-3 mt-4 pt-4 border-t border-gray-100">
          <BulkImport endpoint={`/api/v1/zones/${zoneId}/records/bulk`} onComplete={onBulkComplete} />
          <button 
            onClick={downloadTemplate}
            className="flex items-center space-x-2 text-gray-600 hover:text-gray-800 px-3 py-1.5 rounded-lg hover:bg-gray-100 transition-colors"
          >
            <Download className="w-4 h-4" />
            <span>Template</span>
          </button>
        </div>
      </motion.div>

      <motion.div 
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.1 }}
        className="bg-white shadow-lg rounded-xl border border-gray-100 overflow-hidden"
      >
        {records.length === 0 ? (
          <div className="p-12 text-center">
            <FileText className="w-16 h-16 text-gray-300 mx-auto mb-4" />
            <p className="text-gray-500">No records in this zone yet</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead className="bg-gray-50">
                <tr>
                  <th className="px-6 py-3 text-left text-xs font-semibold text-gray-600 uppercase tracking-wider">ID</th>
                  <th className="px-6 py-3 text-left text-xs font-semibold text-gray-600 uppercase tracking-wider">Name</th>
                  <th className="px-6 py-3 text-left text-xs font-semibold text-gray-600 uppercase tracking-wider">Type</th>
                  <th className="px-6 py-3 text-left text-xs font-semibold text-gray-600 uppercase tracking-wider">Value</th>
                  <th className="px-6 py-3 text-left text-xs font-semibold text-gray-600 uppercase tracking-wider">TTL</th>
                  <th className="px-6 py-3 text-right text-xs font-semibold text-gray-600 uppercase tracking-wider">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-100">
                {records.map((r, i) => (
                  <motion.tr 
                    key={r.id}
                    initial={{ opacity: 0 }}
                    animate={{ opacity: 1 }}
                    transition={{ delay: i * 0.02 }}
                    className="hover:bg-gray-50"
                  >
                    <td className="px-6 py-4 text-sm text-gray-500 font-mono">{r.id?.substring(0,8)}...</td>
                    <td className="px-6 py-4 text-sm font-medium text-gray-900">{r.name || '@'}</td>
                    <td className="px-6 py-4">
                      <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${
                        ['A','AAAA'].includes(r.record_type) ? 'bg-blue-100 text-blue-800' :
                        ['CNAME'].includes(r.record_type) ? 'bg-purple-100 text-purple-800' :
                        ['MX'].includes(r.record_type) ? 'bg-red-100 text-red-800' :
                        ['TXT'].includes(r.record_type) ? 'bg-green-100 text-green-800' :
                        'bg-gray-100 text-gray-800'
                      }`}>
                        {r.record_type}
                      </span>
                    </td>
                    <td className="px-6 py-4 text-sm text-gray-600 font-mono max-w-xs truncate">{r.value}</td>
                    <td className="px-6 py-4 text-sm text-gray-500">{r.ttl}</td>
                    <td className="px-6 py-4 text-right">
                      <button 
                        onClick={()=>remove(r.id)}
                        className="text-red-600 hover:text-red-800 p-1 rounded hover:bg-red-50"
                      >
                        <Trash2 className="w-4 h-4" />
                      </button>
                    </td>
                  </motion.tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </motion.div>
    </div>
  )
}
