import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { 
  Server, 
  Plus, 
  Search, 
  RefreshCw, 
  Trash2, 
  Power,
  Activity,
  Clock,
  CheckCircle,
  XCircle,
  X
} from 'lucide-react';
import api from '../../api/client';

const StatusBadge = ({ status, label }) => {
  const styles = {
    online: 'bg-success-100 text-success-700 dark:bg-success-900/30 dark:text-success-400',
    offline: 'bg-gray-100 text-gray-600 dark:bg-gray-700 dark:text-gray-400',
    enabled: 'bg-primary-100 text-primary-700 dark:bg-primary-900/30 dark:text-primary-400',
    disabled: 'bg-gray-100 text-gray-600 dark:bg-gray-700 dark:text-gray-400',
  };
  
  return (
    <span className={`px-2.5 py-1 rounded-full text-xs font-medium ${styles[status] || styles.offline}`}>
      {label || status}
    </span>
  );
};

const AgentCard = ({ agent, onDelete, onToggle, onRotate, delay = 0 }) => {
  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay }}
      className="bg-white dark:bg-gray-800 rounded-2xl shadow-lg border border-gray-100 dark:border-gray-700 overflow-hidden hover:shadow-xl transition-shadow"
    >
      <div className="p-6">
        <div className="flex items-start justify-between mb-4">
          <div className="flex items-center gap-4">
            <div className={`w-12 h-12 rounded-xl flex items-center justify-center ${
              agent.online ? 'bg-success-100 dark:bg-success-900/30' : 'bg-gray-100 dark:bg-gray-700'
            }`}>
              <Server className={`w-6 h-6 ${agent.online ? 'text-success-600' : 'text-gray-400'}`} />
            </div>
            <div>
              <h3 className="font-semibold text-gray-900 dark:text-white">{agent.name}</h3>
              <p className="text-sm text-gray-500 dark:text-gray-400 font-mono">{agent.addr}</p>
            </div>
          </div>
          <StatusBadge status={agent.online ? 'online' : 'offline'} />
        </div>
        
        <div className="grid grid-cols-2 gap-4 mb-4">
          <div className="bg-gray-50 dark:bg-gray-700/50 rounded-xl p-3">
            <div className="flex items-center gap-2 text-xs text-gray-500 dark:text-gray-400 mb-1">
              <Activity className="w-3 h-3" />
              Status
            </div>
            <p className={`font-semibold ${agent.online ? 'text-success-600' : 'text-gray-500'}`}>
              {agent.online ? 'Online' : 'Offline'}
            </p>
          </div>
          <div className="bg-gray-50 dark:bg-gray-700/50 rounded-xl p-3">
            <div className="flex items-center gap-2 text-xs text-gray-500 dark:text-gray-400 mb-1">
              <Clock className="w-3 h-3" />
              Last Heartbeat
            </div>
            <p className="font-semibold text-gray-900 dark:text-white text-sm">
              {agent.last_heartbeat ? new Date(agent.last_heartbeat).toLocaleString() : 'Never'}
            </p>
          </div>
        </div>
        
        <div className="flex items-center gap-2">
          <button
            onClick={() => onRotate(agent.id)}
            className="flex-1 flex items-center justify-center gap-2 px-3 py-2 text-sm font-medium text-gray-700 dark:text-gray-300 bg-gray-100 dark:bg-gray-700 rounded-xl hover:bg-gray-200 dark:hover:bg-gray-600 transition-colors"
          >
            <RefreshCw className="w-4 h-4" />
            Rotate Token
          </button>
          <button
            onClick={() => onToggle(agent)}
            className={`flex-1 flex items-center justify-center gap-2 px-3 py-2 text-sm font-medium rounded-xl transition-colors ${
              agent.enabled 
                ? 'text-danger-600 bg-danger-50 dark:bg-danger-900/20 hover:bg-danger-100 dark:hover:bg-danger-900/40'
                : 'text-success-600 bg-success-50 dark:bg-success-900/20 hover:bg-success-100 dark:hover:bg-success-900/40'
            }`}
          >
            <Power className="w-4 h-4" />
            {agent.enabled ? 'Disable' : 'Enable'}
          </button>
          <button
            onClick={() => onDelete(agent.id)}
            className="flex-1 flex items-center justify-center gap-2 px-3 py-2 text-sm font-medium text-danger-600 bg-danger-50 dark:bg-danger-900/20 rounded-xl hover:bg-danger-100 dark:hover:bg-danger-900/40 transition-colors"
          >
            <Trash2 className="w-4 h-4" />
            Delete
          </button>
        </div>
      </div>
    </motion.div>
  );
};

const CreateAgentModal = ({ isOpen, onClose, onCreate }) => {
  const [name, setName] = useState('');
  const [addr, setAddr] = useState('');
  const [loading, setLoading] = useState(false);
  
  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    try {
      await onCreate({ name, addr });
      setName('');
      setAddr('');
      onClose();
    } catch (e) {
      console.error(e);
    }
    setLoading(false);
  };
  
  if (!isOpen) return null;
  
  return (
    <motion.div 
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0 }}
      className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/50"
      onClick={onClose}
    >
      <motion.div 
        initial={{ scale: 0.95, opacity: 0 }}
        animate={{ scale: 1, opacity: 1 }}
        exit={{ scale: 0.95, opacity: 0 }}
        className="bg-white dark:bg-gray-800 rounded-2xl shadow-2xl w-full max-w-md"
        onClick={e => e.stopPropagation()}
      >
        <div className="flex items-center justify-between p-6 border-b border-gray-100 dark:border-gray-700">
          <h3 className="text-xl font-semibold text-gray-900 dark:text-white">Register New Agent</h3>
          <button onClick={onClose} className="p-2 hover:bg-gray-100 dark:hover:bg-gray-700 rounded-xl">
            <X className="w-5 h-5 text-gray-500" />
          </button>
        </div>
        
        <form onSubmit={handleSubmit} className="p-6 space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
              Agent Name
            </label>
            <input
              type="text"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="e.g., us-east-1-agent"
              className="w-full px-4 py-3 border border-gray-200 dark:border-gray-600 rounded-xl bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:ring-2 focus:ring-primary-500 focus:border-primary-500"
              required
            />
          </div>
          
          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
              Agent Address
            </label>
            <input
              type="text"
              value={addr}
              onChange={(e) => setAddr(e.target.value)}
              placeholder="e.g., 192.168.1.100:5353"
              className="w-full px-4 py-3 border border-gray-200 dark:border-gray-600 rounded-xl bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:ring-2 focus:ring-primary-500 focus:border-primary-500"
              required
            />
          </div>
          
          <div className="bg-primary-50 dark:bg-primary-900/20 rounded-xl p-4">
            <p className="text-sm text-primary-700 dark:text-primary-300">
              <strong>Note:</strong> The agent must be running and accessible at the provided address.
            </p>
          </div>
          
          <div className="flex gap-3 pt-2">
            <button
              type="button"
              onClick={onClose}
              className="flex-1 px-4 py-3 border border-gray-200 dark:border-gray-600 text-gray-700 dark:text-gray-300 rounded-xl font-medium hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={loading}
              className="flex-1 px-4 py-3 bg-primary-600 text-white rounded-xl font-medium hover:bg-primary-700 transition-colors disabled:opacity-50"
            >
              {loading ? <RefreshCw className="w-5 h-5 animate-spin mx-auto" /> : 'Register Agent'}
            </button>
          </div>
        </form>
      </motion.div>
    </motion.div>
  );
};

export default function Agents() {
  const [agents, setAgents] = useState([]);
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');
  const [modalOpen, setModalOpen] = useState(false);
  
  const loadAgents = async () => {
    setLoading(true);
    try {
      const res = await api.get('/api/v1/agents');
      setAgents(res.data || []);
    } catch (e) {
      console.error('Failed to load agents:', e);
    }
    setLoading(false);
  };
  
  useEffect(() => {
    const token = localStorage.getItem('token');
    if (token) {
      api.defaults.headers.common['Authorization'] = `Bearer ${token}`;
    }
    loadAgents();
  }, []);
  
  const handleCreate = async (data) => {
    try {
      await api.post('/api/v1/agents/register', data);
      await loadAgents();
    } catch (e) {
      console.error('Failed to register agent:', e);
      throw e;
    }
  };
  
  const handleDelete = async (id) => {
    if (!confirm('Are you sure you want to delete this agent?')) return;
    try {
      await api.delete(`/api/v1/agents/${id}`);
      await loadAgents();
    } catch (e) {
      console.error('Failed to delete agent:', e);
    }
  };
  
  const handleToggle = async (agent) => {
    // TODO: Implement agent enable/disable toggle
    console.debug('Toggle agent:', agent.id);
  };
  
  const handleRotateToken = async (id) => {
    try {
      await api.post(`/api/v1/agents/${id}/token/rotate`);
      await loadAgents();
    } catch (e) {
      console.error('Failed to rotate token:', e);
    }
  };
  
  const filteredAgents = agents.filter(agent => 
    agent.name?.toLowerCase().includes(searchTerm.toLowerCase()) ||
    agent.addr?.toLowerCase().includes(searchTerm.toLowerCase()) ||
    agent.id?.toLowerCase().includes(searchTerm.toLowerCase())
  );
  
  const onlineCount = agents.filter(a => a.online).length;
  const offlineCount = agents.length - onlineCount;
  
  return (
    <div className="space-y-6">
      {/* Header */}
      <motion.div 
        initial={{ opacity: 0, y: -20 }}
        animate={{ opacity: 1, y: 0 }}
        className="flex flex-col md:flex-row md:items-center md:justify-between gap-4"
      >
        <div>
          <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Agents</h1>
          <p className="text-gray-500 dark:text-gray-400">Manage DNS agents and remote nodes</p>
        </div>
        <div className="flex items-center gap-3">
          <button 
            onClick={loadAgents}
            className="flex items-center gap-2 px-4 py-2 bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-xl text-sm font-medium text-gray-700 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
            Refresh
          </button>
          <button 
            onClick={() => setModalOpen(true)}
            className="flex items-center gap-2 px-4 py-2 bg-primary-600 text-white rounded-xl text-sm font-medium hover:bg-primary-700 transition-colors"
          >
            <Plus className="w-4 h-4" />
            Register Agent
          </button>
        </div>
      </motion.div>
      
      {/* Stats */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <motion.div 
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.1 }}
          className="bg-white dark:bg-gray-800 rounded-2xl shadow-lg border border-gray-100 dark:border-gray-700 p-6"
        >
          <div className="flex items-center gap-4">
            <div className="w-12 h-12 rounded-xl bg-primary-100 dark:bg-primary-900/30 flex items-center justify-center">
              <Server className="w-6 h-6 text-primary-600" />
            </div>
            <div>
              <p className="text-2xl font-bold text-gray-900 dark:text-white">{agents.length}</p>
              <p className="text-sm text-gray-500 dark:text-gray-400">Total Agents</p>
            </div>
          </div>
        </motion.div>
        
        <motion.div 
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.2 }}
          className="bg-white dark:bg-gray-800 rounded-2xl shadow-lg border border-gray-100 dark:border-gray-700 p-6"
        >
          <div className="flex items-center gap-4">
            <div className="w-12 h-12 rounded-xl bg-success-100 dark:bg-success-900/30 flex items-center justify-center">
              <CheckCircle className="w-6 h-6 text-success-600" />
            </div>
            <div>
              <p className="text-2xl font-bold text-gray-900 dark:text-white">{onlineCount}</p>
              <p className="text-sm text-gray-500 dark:text-gray-400">Online</p>
            </div>
          </div>
        </motion.div>
        
        <motion.div 
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.3 }}
          className="bg-white dark:bg-gray-800 rounded-2xl shadow-lg border border-gray-100 dark:border-gray-700 p-6"
        >
          <div className="flex items-center gap-4">
            <div className="w-12 h-12 rounded-xl bg-gray-100 dark:bg-gray-700 flex items-center justify-center">
              <XCircle className="w-6 h-6 text-gray-500" />
            </div>
            <div>
              <p className="text-2xl font-bold text-gray-900 dark:text-white">{offlineCount}</p>
              <p className="text-sm text-gray-500 dark:text-gray-400">Offline</p>
            </div>
          </div>
        </motion.div>
      </div>
      
      {/* Search */}
      <motion.div 
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.4 }}
        className="relative"
      >
        <Search className="absolute left-4 top-1/2 -translate-y-1/2 w-5 h-5 text-gray-400" />
        <input
          type="text"
          placeholder="Search agents by name, address, or ID..."
          value={searchTerm}
          onChange={(e) => setSearchTerm(e.target.value)}
          className="w-full pl-12 pr-4 py-3 border border-gray-200 dark:border-gray-600 rounded-xl bg-white dark:bg-gray-800 text-gray-900 dark:text-white focus:ring-2 focus:ring-primary-500 focus:border-primary-500"
        />
      </motion.div>
      
      {/* Agent Grid */}
      {loading ? (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {[1, 2, 3].map(i => (
            <div key={i} className="bg-white dark:bg-gray-800 rounded-2xl h-48 animate-pulse" />
          ))}
        </div>
      ) : filteredAgents.length === 0 ? (
        <motion.div 
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          className="bg-white dark:bg-gray-800 rounded-2xl shadow-lg border border-gray-100 dark:border-gray-700 p-12 text-center"
        >
          <Server className="w-16 h-16 text-gray-300 dark:text-gray-600 mx-auto mb-4" />
          <h3 className="text-xl font-semibold text-gray-900 dark:text-white mb-2">No Agents Found</h3>
          <p className="text-gray-500 dark:text-gray-400 mb-6">
            {searchTerm ? 'Try adjusting your search' : 'Register your first agent to get started'}
          </p>
          {!searchTerm && (
            <button 
              onClick={() => setModalOpen(true)}
              className="inline-flex items-center gap-2 px-6 py-3 bg-primary-600 text-white rounded-xl font-medium hover:bg-primary-700 transition-colors"
            >
              <Plus className="w-5 h-5" />
              Register Agent
            </button>
          )}
        </motion.div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {filteredAgents.map((agent, index) => (
            <AgentCard
              key={agent.id}
              agent={agent}
              onDelete={handleDelete}
              onToggle={handleToggle}
              onRotate={handleRotateToken}
              delay={0.1 + index * 0.05}
            />
          ))}
        </div>
      )}
      
      {/* Create Modal */}
      <CreateAgentModal 
        isOpen={modalOpen} 
        onClose={() => setModalOpen(false)} 
        onCreate={handleCreate}
      />
    </div>
  );
}
