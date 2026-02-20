import React from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import api from '../../api/client'
import Modal from '../../components/Modal'
import SearchInput from '../../components/SearchInput'
import { Users as UsersIcon, Plus, Edit2, Trash2, Shield, Mail, User } from 'lucide-react'

export default function Users(){
  const [users, setUsers] = React.useState([])
  const [q, setQ] = React.useState('')
  const [open, setOpen] = React.useState(false)
  const [editing, setEditing] = React.useState(null)
  const [form, setForm] = React.useState({ username:'', email:'', role:'user', password:'' })
  const [loading, setLoading] = React.useState(false)

  const load = async () => {
    setLoading(true)
    try { 
      const r = await api.get('/api/v1/users')
      setUsers(r.data || []) 
    } catch(e){ console.error(e) }
    setLoading(false)
  }
  React.useEffect(()=>{ const t=localStorage.getItem('token'); if(t) api.setToken(t); load() }, [])

  const openCreate = ()=>{ setForm({ username:'', email:'', role:'user', password:'' }); setEditing(null); setOpen(true) }
  const openEdit = (u)=>{ setForm({ username:u.username, email:u.email || '', role:u.role, password:'' }); setEditing(u); setOpen(true) }

  const save = async ()=>{
    try {
      if (editing) {
        // For editing, only update fields that are provided
        const updateData = { username: form.username, role: form.role }
        await api.put(`/api/v1/users/${editing.id}`, updateData)
      } else {
        // For creating, password is required
        if (!form.password || form.password.length < 8) {
          alert('Password must be at least 8 characters')
          return
        }
        await api.post('/api/v1/users', { username: form.username, password: form.password, role: form.role })
      }
      setOpen(false)
      load()
    } catch(e){ alert('Save failed: ' + (e.response?.data?.error || e.message)) }
  }

  const remove = async (id)=>{ if(!confirm('Delete user?')) return; try { await api.delete(`/api/v1/users/${id}`); load() } catch(e){ alert('Delete failed') } }

  const filtered = users.filter(u=> (u.username||'').toLowerCase().includes(q.toLowerCase()) || (u.email||'').toLowerCase().includes(q.toLowerCase()))

  return (
    <div className="space-y-6">
      <motion.div 
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        className="bg-white shadow-lg rounded-xl p-6 border border-gray-100"
      >
        <div className="flex items-center justify-between mb-6">
          <div className="flex items-center space-x-3">
            <div className="p-2 bg-purple-100 rounded-lg">
              <UsersIcon className="w-6 h-6 text-purple-600" />
            </div>
            <h3 className="text-xl font-bold text-gray-800">User Management</h3>
          </div>
          <button 
            onClick={openCreate}
            className="bg-gradient-to-r from-purple-600 to-purple-700 text-white px-4 py-2 rounded-lg hover:from-purple-700 hover:to-purple-800 transition-all flex items-center space-x-2 font-medium"
          >
            <Plus className="w-5 h-5" />
            <span>New User</span>
          </button>
        </div>

        <div className="max-w-md">
          <SearchInput value={q} onChange={setQ} placeholder="Search users..." />
        </div>
      </motion.div>

      <motion.div 
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.1 }}
        className="bg-white shadow-lg rounded-xl border border-gray-100 overflow-hidden"
      >
        {filtered.length === 0 ? (
          <div className="p-12 text-center">
            <UsersIcon className="w-16 h-16 text-gray-300 mx-auto mb-4" />
            <p className="text-gray-500">No users found</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead className="bg-gray-50">
                <tr>
                  <th className="px-6 py-3 text-left text-xs font-semibold text-gray-600 uppercase tracking-wider">ID</th>
                  <th className="px-6 py-3 text-left text-xs font-semibold text-gray-600 uppercase tracking-wider">Username</th>
                  <th className="px-6 py-3 text-left text-xs font-semibold text-gray-600 uppercase tracking-wider">Email</th>
                  <th className="px-6 py-3 text-left text-xs font-semibold text-gray-600 uppercase tracking-wider">Role</th>
                  <th className="px-6 py-3 text-right text-xs font-semibold text-gray-600 uppercase tracking-wider">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-100">
                {filtered.map((u, i) => (
                  <motion.tr 
                    key={u.id}
                    initial={{ opacity: 0 }}
                    animate={{ opacity: 1 }}
                    transition={{ delay: i * 0.05 }}
                    className="hover:bg-gray-50"
                  >
                    <td className="px-6 py-4 text-sm text-gray-500 font-mono">{u.id?.substring(0,8)}...</td>
                    <td className="px-6 py-4">
                      <div className="flex items-center space-x-2">
                        <User className="w-4 h-4 text-gray-400" />
                        <span className="text-sm font-medium text-gray-900">{u.username}</span>
                      </div>
                    </td>
                    <td className="px-6 py-4">
                      <div className="flex items-center space-x-2">
                        <Mail className="w-4 h-4 text-gray-400" />
                        <span className="text-sm text-gray-600">{u.email}</span>
                      </div>
                    </td>
                    <td className="px-6 py-4">
                      <span className={`inline-flex items-center space-x-1 px-2.5 py-0.5 rounded-full text-xs font-medium ${
                        u.role === 'admin' ? 'bg-purple-100 text-purple-800' : 'bg-blue-100 text-blue-800'
                      }`}>
                        <Shield className="w-3 h-3" />
                        <span>{u.role}</span>
                      </span>
                    </td>
                    <td className="px-6 py-4 text-right">
                      <div className="flex items-center justify-end space-x-2">
                        <button 
                          onClick={()=>openEdit(u)}
                          className="text-blue-600 hover:text-blue-800 p-1 rounded hover:bg-blue-50"
                        >
                          <Edit2 className="w-4 h-4" />
                        </button>
                        <button 
                          onClick={()=>remove(u.id)}
                          className="text-red-600 hover:text-red-800 p-1 rounded hover:bg-red-50"
                        >
                          <Trash2 className="w-4 h-4" />
                        </button>
                      </div>
                    </td>
                  </motion.tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </motion.div>

      <AnimatePresence>
        {open && (
          <Modal title={editing ? 'Edit User' : 'Create User'} open={open} onClose={()=>setOpen(false)}>
            <motion.div
              initial={{ opacity: 0, scale: 0.95 }}
              animate={{ opacity: 1, scale: 1 }}
              exit={{ opacity: 0, scale: 0.95 }}
              className="space-y-4"
            >
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">Username</label>
                <input 
                  className="w-full border border-gray-300 rounded-lg px-4 py-2 focus:ring-2 focus:ring-purple-500 focus:border-transparent" 
                  placeholder="username" 
                  value={form.username} 
                  onChange={e=>setForm({...form, username:e.target.value})} 
                />
              </div>
              {!editing && (
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">Password</label>
                  <input 
                    type="password"
                    className="w-full border border-gray-300 rounded-lg px-4 py-2 focus:ring-2 focus:ring-purple-500 focus:border-transparent" 
                    placeholder="min 8 characters" 
                    value={form.password} 
                    onChange={e=>setForm({...form, password:e.target.value})} 
                  />
                </div>
              )}
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">Role</label>
                <select 
                  className="w-full border border-gray-300 rounded-lg px-4 py-2 focus:ring-2 focus:ring-purple-500 focus:border-transparent" 
                  value={form.role} 
                  onChange={e=>setForm({...form, role:e.target.value})}
                >
                  <option value="user">User</option>
                  <option value="admin">Admin</option>
                </select>
              </div>
              <div className="flex justify-end space-x-3 pt-4">
                <button 
                  className="px-4 py-2 text-gray-700 bg-gray-100 rounded-lg hover:bg-gray-200 transition-colors" 
                  onClick={()=>setOpen(false)}
                >
                  Cancel
                </button>
                <button 
                  className="px-4 py-2 bg-purple-600 text-white rounded-lg hover:bg-purple-700 transition-colors" 
                  onClick={save}
                >
                  Save
                </button>
              </div>
            </motion.div>
          </Modal>
        )}
      </AnimatePresence>
    </div>
  )
}
