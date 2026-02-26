import React from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import api from '../../api/client'
import { Globe, Plus, Trash2, MapPin, Play, ChevronRight } from 'lucide-react'

export default function GeoRules(){
  const [rules, setRules] = React.useState([])
  const [zones, setZones] = React.useState([])
  const [zone, setZone] = React.useState('')
  const [matchType, setMatchType] = React.useState('country')
  const [matchValue, setMatchValue] = React.useState('US')
  const [target, setTarget] = React.useState('192.0.2.1')
  const [priority, setPriority] = React.useState(0)
  const [enabled, setEnabled] = React.useState(true)
  const [recordName, setRecordName] = React.useState('')
  const [recordType, setRecordType] = React.useState('')
  const [testIp, setTestIp] = React.useState('8.8.8.8')
  const [resolveResult, setResolveResult] = React.useState(null)
  const [loading, setLoading] = React.useState(false)
  const [testing, setTesting] = React.useState(false)

  const load = async () => {
    setLoading(true)
    try { 
      const r = await api.get('/api/v1/georules'); 
      setRules(r.data || []) 
    } catch (e) { console.error(e) }
    try { 
      const z = await api.get('/api/v1/zones'); 
      setZones(z.data || []) 
    } catch (e) { console.warn('zones load failed', e) }
    setLoading(false)
  }
  React.useEffect(()=>{ 
    const t=localStorage.getItem('token')
    if(t) api.setToken(t)
    load() 
  }, [])

  const create = async () => {
    if (!zone || !matchValue || !target) return
    try { 
      await api.post('/api/v1/georules', { 
        zone_id: zone, match_type: matchType, match_value: matchValue, target,
        priority, enabled, record_name: recordName || null, record_type: recordType || null
      }); 
      setZone(''); setPriority(0); setEnabled(true); setRecordName(''); setRecordType('');
      load() 
    } catch (e) { alert('Error creating rule') }
  }

  const remove = async (id)=>{ 
    if(!confirm('Delete rule?')) return; 
    try { 
      await api.delete(`/api/v1/georules/${id}`); 
      load() 
    } catch(e){ alert('Delete failed') } 
  }

  const testResolve = async () => {
    if (!zone) { alert('Select a zone'); return }
    setTesting(true)
    try { 
      const r = await api.post('/api/v1/georules/resolve', { zone_id: zone, client_ip: testIp }); 
      setResolveResult(r.data) 
    } catch (e) { alert('Error resolving') }
    setTesting(false)
  }

  const getZoneName = (zoneId) => {
    const z = zones.find(z => z.id === zoneId)
    return z ? z.domain : zoneId
  }

  const toggleEnabled = async (rule) => {
    try {
      await api.put(`/api/v1/georules/${rule.id}`, { enabled: !rule.enabled });
      load();
    } catch (e) {
      alert('Failed to update rule');
    }
  }

  return (
    <div className="space-y-6">
      <motion.div 
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        className="bg-white shadow-lg rounded-xl p-6 border border-gray-100"
      >
        <div className="flex items-center space-x-3 mb-6">
          <div className="p-2 bg-green-100 rounded-lg">
            <Globe className="w-6 h-6 text-green-600" />
          </div>
          <h3 className="text-xl font-bold text-gray-800">GeoDNS Rules</h3>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-7 gap-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Zone</label>
            <select 
              className="w-full border border-gray-300 rounded-lg px-4 py-2 focus:ring-2 focus:ring-green-500 focus:border-transparent" 
              value={zone} 
              onChange={e=>setZone(e.target.value)}
            >
              <option value="">Select a zone</option>
              {zones.map(z=> <option key={z.id} value={z.id}>{z.domain}</option>)}
            </select>
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Match Type</label>
            <select 
              className="w-full border border-gray-300 rounded-lg px-4 py-2 focus:ring-2 focus:ring-green-500 focus:border-transparent" 
              value={matchType} 
              onChange={e=>setMatchType(e.target.value)}
            >
              <option value="country">Country</option>
              <option value="region">Region</option>
              <option value="continent">Continent</option>
            </select>
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Match Value</label>
            <input 
              className="w-full border border-gray-300 rounded-lg px-4 py-2 focus:ring-2 focus:ring-green-500 focus:border-transparent" 
              placeholder="e.g., US, EU, NA" 
              value={matchValue} 
              onChange={e=>setMatchValue(e.target.value)} 
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Target IP</label>
            <input 
              className="w-full border border-gray-300 rounded-lg px-4 py-2 focus:ring-2 focus:ring-green-500 focus:border-transparent" 
              placeholder="e.g., 192.0.2.1" 
              value={target} 
              onChange={e=>setTarget(e.target.value)} 
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Priority</label>
            <input type="number" min="0" className="w-full border border-gray-300 rounded-lg px-4 py-2 focus:ring-2 focus:ring-green-500 focus:border-transparent" value={priority} onChange={e=>setPriority(parseInt(e.target.value)||0)} />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Enabled</label>
            <input type="checkbox" checked={enabled} onChange={e=>setEnabled(e.target.checked)} className="h-5 w-5" />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Record Name</label>
            <input className="w-full border border-gray-300 rounded-lg px-4 py-2 focus:ring-2 focus:ring-green-500 focus:border-transparent" placeholder="optional" value={recordName} onChange={e=>setRecordName(e.target.value)} />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Record Type</label>
            <input className="w-full border border-gray-300 rounded-lg px-4 py-2 focus:ring-2 focus:ring-green-500 focus:border-transparent" placeholder="e.g., A, AAAA" value={recordType} onChange={e=>setRecordType(e.target.value)} />
          </div>
          <div className="flex items-end">
            <button 
              className="w-full bg-gradient-to-r from-green-600 to-green-700 text-white px-4 py-2 rounded-lg hover:from-green-700 hover:to-green-800 transition-all flex items-center justify-center space-x-2 font-medium"
              onClick={create}
            >
              <Plus className="w-5 h-5" />
              <span>Add Rule</span>
            </button>
          </div>
        </div>
      </motion.div>

      <motion.div 
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.1 }}
        className="bg-white shadow-lg rounded-xl p-6 border border-gray-100"
      >
        <div className="flex items-center space-x-3 mb-6">
          <div className="p-2 bg-blue-100 rounded-lg">
            <Play className="w-6 h-6 text-blue-600" />
          </div>
          <h3 className="text-xl font-bold text-gray-800">Test Resolution</h3>
        </div>

        <div className="flex flex-wrap items-end gap-4">
          <div className="flex-1 min-w-[200px]">
            <label className="block text-sm font-medium text-gray-700 mb-1">Client IP Address</label>
            <input 
              className="w-full border border-gray-300 rounded-lg px-4 py-2 focus:ring-2 focus:ring-blue-500 focus:border-transparent" 
              placeholder="e.g., 8.8.8.8" 
              value={testIp} 
              onChange={e=>setTestIp(e.target.value)} 
            />
          </div>
          <button 
            className="bg-gradient-to-r from-blue-600 to-blue-700 text-white px-6 py-2 rounded-lg hover:from-blue-700 hover:to-blue-800 transition-all flex items-center space-x-2 font-medium"
            onClick={testResolve}
            disabled={testing}
          >
            <Play className={`w-5 h-5 ${testing ? 'animate-pulse' : ''}`} />
            <span>Resolve</span>
          </button>
        </div>

        <AnimatePresence>
          {resolveResult && (
            <motion.div 
              initial={{ opacity: 0, height: 0 }}
              animate={{ opacity: 1, height: 'auto' }}
              exit={{ opacity: 0, height: 0 }}
              className="mt-4"
            >
              <div className="bg-gray-900 rounded-lg p-4 overflow-x-auto">
                <pre className="text-green-400 text-sm font-mono">{JSON.stringify(resolveResult, null, 2)}</pre>
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </motion.div>

      <motion.div 
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.2 }}
        className="bg-white shadow-lg rounded-xl border border-gray-100 overflow-hidden"
      >
        {rules.length === 0 ? (
          <div className="p-12 text-center">
            <Globe className="w-16 h-16 text-gray-300 mx-auto mb-4" />
            <p className="text-gray-500">No GeoDNS rules configured yet</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead className="bg-gray-50">
                <tr>
                  <th className="px-6 py-3 text-left text-xs font-semibold text-gray-600 uppercase tracking-wider">Zone</th>
                  <th className="px-6 py-3 text-left text-xs font-semibold text-gray-600 uppercase tracking-wider">Match</th>
                  <th className="px-6 py-3 text-left text-xs font-semibold text-gray-600 uppercase tracking-wider">Value</th>
                  <th className="px-6 py-3 text-left text-xs font-semibold text-gray-600 uppercase tracking-wider">Target</th>
                  <th className="px-6 py-3 text-left text-xs font-semibold text-gray-600 uppercase tracking-wider">Pri</th>
                  <th className="px-6 py-3 text-left text-xs font-semibold text-gray-600 uppercase tracking-wider">Enabled</th>
                  <th className="px-6 py-3 text-left text-xs font-semibold text-gray-600 uppercase tracking-wider">Record</th>
                  <th className="px-6 py-3 text-right text-xs font-semibold text-gray-600 uppercase tracking-wider">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-100">
                {rules.map((r, i) => (
                  <motion.tr 
                    key={r.id}
                    initial={{ opacity: 0 }}
                    animate={{ opacity: 1 }}
                    transition={{ delay: i * 0.05 }}
                    className="hover:bg-gray-50"
                  >
                    <td className="px-6 py-4 text-sm font-medium text-gray-900">{getZoneName(r.zone_id)}</td>
                    <td className="px-6 py-4">
                      <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-green-100 text-green-800 capitalize">
                        {r.match_type}
                      </span>
                    </td>
                    <td className="px-6 py-4 text-sm text-gray-600">
                      <div className="flex items-center space-x-1">
                        <MapPin className="w-4 h-4 text-gray-400" />
                        <span>{r.match_value}</span>
                      </div>
                    </td>
                    <td className="px-6 py-4 text-sm text-gray-600 font-mono">{r.target}</td>
                    <td className="px-6 py-4 text-sm text-gray-600">{r.priority}</td>
                    <td className="px-6 py-4">
                      <input type="checkbox" checked={r.enabled} onChange={()=>toggleEnabled(r)} className="h-4 w-4" />
                    </td>
                    <td className="px-6 py-4 text-sm text-gray-600">
                      {r.record_name || '-'}{r.record_type ? `/${r.record_type}` : ''}
                    </td>
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
