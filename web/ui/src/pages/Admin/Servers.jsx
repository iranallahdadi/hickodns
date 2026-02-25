import React from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import api from '../../api/client'
import { Server, MapPin, Plus, Trash2, RefreshCw, Play, Square, Shield, Clock, FileText, Settings, X, Check, AlertTriangle } from 'lucide-react'

export default function Servers(){
  const [servers, setServers] = React.useState([])
  const [loading, setLoading] = React.useState(false)
  const [showModal, setShowModal] = React.useState(false)
  const [editingServer, setEditingServer] = React.useState(null)
  const [form, setForm] = React.useState({
    name: '', address: '', port: 53, region: '',
    enabled: true, dnssec: false, enable_logging: true,
    max_cache_ttl: 3600, min_cache_ttl: 60
  })
  // DNS control is handled externally; only configuration is managed here

  const load = async () => {
    setLoading(true)
    try {
      const r = await api.get('/api/v1/servers')
      setServers(r.data || [])
    } catch (e) { console.error(e) }
    setLoading(false)
  }

  React.useEffect(()=>{ 
    const token = localStorage.getItem('token')
    if(token) api.setToken(token)
    load() 
  }, [])

  const openCreate = () => {
    setForm({
      name: '', address: '', port: 53, region: '',
      enabled: true, dnssec: false, enable_logging: true,
      max_cache_ttl: 3600, min_cache_ttl: 60
    })
    setEditingServer(null)
    setShowModal(true)
  }

  const openEdit = (server) => {
    setForm({
      name: server.name,
      address: server.address,
      port: server.port || 53,
      region: server.region || '',
      enabled: server.enabled !== false,
      dnssec: server.dnssec === true,
      enable_logging: server.enable_logging !== false,
      max_cache_ttl: server.max_cache_ttl || 3600,
      min_cache_ttl: server.min_cache_ttl || 60
    })
    setEditingServer(server)
    setShowModal(true)
  }

  const save = async () => {
    if (!form.name || !form.address) return
    try { 
      if (editingServer) {
        // Update - for now just recreate
      }
      await api.post('/api/v1/servers', form)
      setShowModal(false)
      load() 
    } catch (e) { alert('Error saving server') }
  }

  const remove = async (id) => {
    if (!confirm('Delete this server?')) return
    try {
      await api.delete(`/api/v1/servers/${id}`)
      load()
    } catch (e) { alert('Error deleting server') }
  }


  const getStatus = (server) => {
    return server.status === 'running' ? 'running' : 'stopped'
  }

  return (
    <div className="space-y-6">
      <motion.div 
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        className="bg-gradient-to-r from-blue-600 to-blue-800 rounded-xl p-6 text-white"
      >
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-4">
            <div className="p-3 bg-white/20 rounded-lg">
              <Server className="w-8 h-8" />
            </div>
            <div>
              <h2 className="text-2xl font-bold">DNS Server Management</h2>
              <p className="text-blue-100">Configure and manage multiple DNS server instances</p>
            </div>
          </div>
          <div className="flex items-center space-x-3">
            <button 
              onClick={load}
              className="p-2 bg-white/20 hover:bg-white/30 rounded-lg transition-colors"
            >
              <RefreshCw className={`w-5 h-5 ${loading ? 'animate-spin' : ''}`} />
            </button>
            <button 
              onClick={openCreate}
              className="flex items-center space-x-2 bg-white text-blue-600 px-4 py-2 rounded-lg hover:bg-blue-50 transition-colors font-medium"
            >
              <Plus className="w-5 h-5" />
              <span>Add Server</span>
            </button>
          </div>
        </div>
      </motion.div>

      {servers.length === 0 ? (
        <motion.div 
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          className="bg-white rounded-xl p-12 text-center border border-gray-200"
        >
          <Server className="w-16 h-16 text-gray-300 mx-auto mb-4" />
          <h3 className="text-lg font-semibold text-gray-700 mb-2">No DNS Servers Configured</h3>
          <p className="text-gray-500 mb-4">Add your first DNS server to start serving zone data</p>
          <button 
            onClick={openCreate}
            className="inline-flex items-center space-x-2 bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700 transition-colors"
          >
            <Plus className="w-5 h-5" />
            <span>Add Server</span>
          </button>
        </motion.div>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {servers.map((server, i) => (
            <motion.div
              key={server.id}
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: i * 0.1 }}
              className="bg-white rounded-xl shadow-lg border border-gray-200 overflow-hidden"
            >
              <div className="p-6">
                <div className="flex items-start justify-between mb-4">
                  <div className="flex items-center space-x-3">
                    <div className={`w-3 h-3 rounded-full ${getStatus(server) === 'running' ? 'bg-green-500 animate-pulse' : 'bg-gray-300'}`}></div>
                    <div>
                      <h3 className="text-lg font-bold text-gray-900">{server.name}</h3>
                      <p className="text-sm text-gray-500">{server.address}:{server.port || 53}</p>
                    </div>
                  </div>
                  <span className={`px-3 py-1 rounded-full text-xs font-medium ${
                    getStatus(server) === 'running' 
                      ? 'bg-green-100 text-green-700' 
                      : 'bg-gray-100 text-gray-600'
                  }`}>
                    {getStatus(server) === 'running' ? 'Running' : 'Stopped'}
                  </span>
                </div>

                <div className="grid grid-cols-2 gap-4 mb-4">
                  <div className="flex items-center space-x-2 text-sm text-gray-600">
                    <MapPin className="w-4 h-4 text-gray-400" />
                    <span>{server.region || 'No region'}</span>
                  </div>
                  <div className="flex items-center space-x-2 text-sm text-gray-600">
                    <Clock className="w-4 h-4 text-gray-400" />
                    <span>Cache: {server.min_cache_ttl || 60}s - {server.max_cache_ttl || 3600}s</span>
                  </div>
                  <div className="flex items-center space-x-2 text-sm text-gray-600">
                    {server.dnssec ? <Shield className="w-4 h-4 text-green-500" /> : <AlertTriangle className="w-4 h-4 text-yellow-500" />}
                    <span>{server.dnssec ? 'DNSSEC Enabled' : 'DNSSEC Disabled'}</span>
                  </div>
                  <div className="flex items-center space-x-2 text-sm text-gray-600">
                    <FileText className="w-4 h-4 text-gray-400" />
                    <span>{server.enable_logging !== false ? 'Logging On' : 'Logging Off'}</span>
                  </div>
                </div>

                <div className="flex items-center space-x-2 pt-4 border-t border-gray-100">
                  {/* DNS control is managed outside of this API in Option B architecture. */}
                  <span className="text-sm text-gray-500">DNS process is external; edit zone configuration only.</span>
                  <button 
                    onClick={() => openEdit(server)}
                    className="flex items-center justify-center space-x-2 px-4 py-2 bg-gray-50 text-gray-600 rounded-lg hover:bg-gray-100 transition-colors"
                  >
                    <Settings className="w-4 h-4" />
                    <span>Config</span>
                  </button>
                  <button 
                    onClick={() => remove(server.id)}
                    className="flex items-center justify-center p-2 text-red-600 hover:bg-red-50 rounded-lg transition-colors"
                  >
                    <Trash2 className="w-4 h-4" />
                  </button>
                </div>
              </div>
            </motion.div>
          ))}
        </div>
      )}

      <AnimatePresence>
        {showModal && (
          <motion.div 
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4"
            onClick={() => setShowModal(false)}
          >
            <motion.div 
              initial={{ scale: 0.95, opacity: 0 }}
              animate={{ scale: 1, opacity: 1 }}
              exit={{ scale: 0.95, opacity: 0 }}
              className="bg-white rounded-2xl shadow-2xl w-full max-w-2xl max-h-[90vh] overflow-y-auto"
              onClick={e => e.stopPropagation()}
            >
              <div className="flex items-center justify-between p-6 border-b">
                <h3 className="text-xl font-bold text-gray-900">
                  {editingServer ? 'Edit Server' : 'Add DNS Server'}
                </h3>
                <button onClick={() => setShowModal(false)} className="p-2 hover:bg-gray-100 rounded-lg">
                  <X className="w-5 h-5 text-gray-500" />
                </button>
              </div>

              <div className="p-6 space-y-6">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">Server Name</label>
                    <input 
                      className="w-full border border-gray-300 rounded-lg px-4 py-2 focus:ring-2 focus:ring-blue-500 focus:border-transparent" 
                      placeholder="e.g., US-East-1 Primary" 
                      value={form.name} 
                      onChange={e=>setForm({...form, name: e.target.value})} 
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">IP Address</label>
                    <input 
                      className="w-full border border-gray-300 rounded-lg px-4 py-2 focus:ring-2 focus:ring-blue-500 focus:border-transparent" 
                      placeholder="e.g., 192.168.1.10" 
                      value={form.address} 
                      onChange={e=>setForm({...form, address: e.target.value})} 
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">Port</label>
                    <input 
                      type="number"
                      className="w-full border border-gray-300 rounded-lg px-4 py-2 focus:ring-2 focus:ring-blue-500 focus:border-transparent" 
                      placeholder="53" 
                      value={form.port} 
                      onChange={e=>setForm({...form, port: parseInt(e.target.value) || 53})} 
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">Region</label>
                    <input 
                      className="w-full border border-gray-300 rounded-lg px-4 py-2 focus:ring-2 focus:ring-blue-500 focus:border-transparent" 
                      placeholder="e.g., us-east" 
                      value={form.region} 
                      onChange={e=>setForm({...form, region: e.target.value})} 
                    />
                  </div>
                </div>

                <div className="border-t pt-6">
                  <h4 className="text-sm font-semibold text-gray-900 mb-4">DNS Configuration</h4>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div>
                      <label className="block text-sm font-medium text-gray-700 mb-1">Max Cache TTL (seconds)</label>
                      <input 
                        type="number"
                        className="w-full border border-gray-300 rounded-lg px-4 py-2 focus:ring-2 focus:ring-blue-500 focus:border-transparent" 
                        value={form.max_cache_ttl} 
                        onChange={e=>setForm({...form, max_cache_ttl: parseInt(e.target.value) || 3600})} 
                      />
                    </div>
                    <div>
                      <label className="block text-sm font-medium text-gray-700 mb-1">Min Cache TTL (seconds)</label>
                      <input 
                        type="number"
                        className="w-full border border-gray-300 rounded-lg px-4 py-2 focus:ring-2 focus:ring-blue-500 focus:border-transparent" 
                        value={form.min_cache_ttl} 
                        onChange={e=>setForm({...form, min_cache_ttl: parseInt(e.target.value) || 60})} 
                      />
                    </div>
                  </div>
                </div>

                <div className="border-t pt-6">
                  <h4 className="text-sm font-semibold text-gray-900 mb-4">Security & Logging</h4>
                  <div className="space-y-3">
                    <label className="flex items-center space-x-3 p-3 rounded-lg border border-gray-200 cursor-pointer hover:bg-gray-50">
                      <input 
                        type="checkbox" 
                        checked={form.enabled} 
                        onChange={e=>setForm({...form, enabled: e.target.checked})}
                        className="w-5 h-5 text-blue-600 rounded focus:ring-blue-500"
                      />
                      <div>
                        <span className="font-medium text-gray-900">Enable Server</span>
                        <p className="text-sm text-gray-500">Allow this server to respond to queries</p>
                      </div>
                    </label>
                    <label className="flex items-center space-x-3 p-3 rounded-lg border border-gray-200 cursor-pointer hover:bg-gray-50">
                      <input 
                        type="checkbox" 
                        checked={form.dnssec} 
                        onChange={e=>setForm({...form, dnssec: e.target.checked})}
                        className="w-5 h-5 text-blue-600 rounded focus:ring-blue-500"
                      />
                      <div>
                        <span className="font-medium text-gray-900">Enable DNSSEC</span>
                        <p className="text-sm text-gray-500">Sign zone data with DNSSEC</p>
                      </div>
                    </label>
                    <label className="flex items-center space-x-3 p-3 rounded-lg border border-gray-200 cursor-pointer hover:bg-gray-50">
                      <input 
                        type="checkbox" 
                        checked={form.enable_logging} 
                        onChange={e=>setForm({...form, enable_logging: e.target.checked})}
                        className="w-5 h-5 text-blue-600 rounded focus:ring-blue-500"
                      />
                      <div>
                        <span className="font-medium text-gray-900">Enable Query Logging</span>
                        <p className="text-sm text-gray-500">Log all DNS queries received</p>
                      </div>
                    </label>
                  </div>
                </div>
              </div>

              <div className="flex items-center justify-end space-x-3 p-6 border-t bg-gray-50">
                <button 
                  onClick={() => setShowModal(false)}
                  className="px-4 py-2 text-gray-700 hover:bg-gray-200 rounded-lg transition-colors"
                >
                  Cancel
                </button>
                <button 
                  onClick={save}
                  className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors flex items-center space-x-2"
                >
                  <Check className="w-4 h-4" />
                  <span>{editingServer ? 'Update' : 'Create'} Server</span>
                </button>
              </div>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  )
}
