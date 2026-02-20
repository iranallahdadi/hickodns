import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { 
  Globe, 
  FileText, 
  Server, 
  Users, 
  Activity, 
  TrendingUp, 
  Clock,
  CheckCircle,
  AlertCircle,
  Database,
  Network,
  Zap,
  ArrowRight,
  RefreshCw,
  Play,
  Square,
  Pause
} from 'lucide-react';
import { Link } from 'react-router-dom';
import api from '../../api/client';
import { LineChart, Line, AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';

const StatCard = ({ icon: Icon, label, value, trend, color = 'primary', delay = 0, onClick }) => {
  const colors = {
    primary: 'from-primary-500 to-primary-600',
    success: 'from-success-500 to-success-600',
    warning: 'from-warning-500 to-warning-600',
    danger: 'from-danger-500 to-danger-600',
  };
  
  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.4, delay }}
      onClick={onClick}
      className={`bg-white dark:bg-gray-800 rounded-2xl shadow-lg border border-gray-100 dark:border-gray-700 overflow-hidden cursor-pointer hover:shadow-xl transition-shadow ${onClick ? 'cursor-pointer' : ''}`}
    >
      <div className="p-6">
        <div className="flex items-center justify-between mb-4">
          <div className={`w-12 h-12 rounded-xl bg-gradient-to-br ${colors[color]} flex items-center justify-center shadow-lg`}>
            <Icon className="w-6 h-6 text-white" />
          </div>
          {trend && (
            <span className="flex items-center text-sm font-medium text-success-600 dark:text-success-400">
              <TrendingUp className="w-4 h-4 mr-1" />
              {trend}
            </span>
          )}
        </div>
        <div className="space-y-1">
          <p className="text-3xl font-bold text-gray-900 dark:text-white">{value || '0'}</p>
          <p className="text-sm text-gray-500 dark:text-gray-400">{label}</p>
        </div>
      </div>
      <div className={`h-1 bg-gradient-to-r ${colors[color]}`}></div>
    </motion.div>
  );
};

const QuickAction = ({ icon: Icon, label, description, to, color = 'primary', delay = 0, onClick }) => {
  const colors = {
    primary: 'group-hover:bg-primary-50 dark:group-hover:bg-primary-900/20',
    success: 'group-hover:bg-success-50 dark:group-hover:bg-success-900/20',
    warning: 'group-hover:bg-warning-50 dark:group-hover:bg-warning-900/20',
  };
  
  const iconColors = {
    primary: 'text-primary-600 dark:text-primary-400',
    success: 'text-success-600 dark:text-success-400',
    warning: 'text-warning-600 dark:text-warning-400',
  };
  
  return (
    <motion.div
      initial={{ opacity: 0, x: -20 }}
      animate={{ opacity: 1, x: 0 }}
      transition={{ duration: 0.4, delay }}
    >
      <Link
        to={to}
        onClick={onClick}
        className={`group flex items-center gap-4 p-4 rounded-xl transition-all duration-200 ${colors[color]} hover:shadow-md`}
      >
        <div className="w-10 h-10 rounded-lg bg-gray-100 dark:bg-gray-700 flex items-center justify-center group-hover:scale-110 transition-transform">
          <Icon className={`w-5 h-5 ${iconColors[color]}`} />
        </div>
        <div className="flex-1">
          <h3 className="font-semibold text-gray-900 dark:text-white">{label}</h3>
          <p className="text-sm text-gray-500 dark:text-gray-400">{description}</p>
        </div>
        <ArrowRight className="w-5 h-5 text-gray-400 group-hover:translate-x-1 transition-transform" />
      </Link>
    </motion.div>
  );
};

const ServerCard = ({ server, onStart, onStop, onRestart, delay = 0 }) => {
  const [actionLoading, setActionLoading] = useState(null);
  
  const handleAction = async (action, fn) => {
    setActionLoading(action);
    try {
      await fn(server.id);
    } catch (e) {
      console.error(e);
    }
    setActionLoading(null);
  };
  
  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.4, delay }}
      className="p-4 rounded-xl bg-gray-50 dark:bg-gray-700/50 border border-gray-100 dark:border-gray-600"
    >
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-3">
          <div className={`w-3 h-3 rounded-full ${server.status === 'running' ? 'bg-success-500 animate-pulse' : 'bg-gray-300'}`}></div>
          <div>
            <p className="font-semibold text-gray-900 dark:text-white">{server.name}</p>
            <p className="text-sm text-gray-500 dark:text-gray-400">{server.address}</p>
          </div>
        </div>
        <span className={`px-2.5 py-1 rounded-full text-xs font-medium ${
          server.status === 'running' 
            ? 'bg-success-100 text-success-700 dark:bg-success-900/30 dark:text-success-400' 
            : 'bg-gray-100 text-gray-600 dark:bg-gray-600 dark:text-gray-300'
        }`}>
          {server.status === 'running' ? 'Active' : 'Inactive'}
        </span>
      </div>
      <div className="flex gap-2">
        {server.status === 'running' ? (
          <button 
            onClick={() => handleAction('stop', onStop)}
            disabled={actionLoading === 'stop'}
            className="flex-1 flex items-center justify-center gap-1 px-3 py-2 text-xs font-medium text-danger-600 bg-danger-50 dark:bg-danger-900/20 rounded-lg hover:bg-danger-100 dark:hover:bg-danger-900/40 transition-colors disabled:opacity-50"
          >
            {actionLoading === 'stop' ? <RefreshCw className="w-3 h-3 animate-spin" /> : <Square className="w-3 h-3" />}
            Stop
          </button>
        ) : (
          <button 
            onClick={() => handleAction('start', onStart)}
            disabled={actionLoading === 'start'}
            className="flex-1 flex items-center justify-center gap-1 px-3 py-2 text-xs font-medium text-success-600 bg-success-50 dark:bg-success-900/20 rounded-lg hover:bg-success-100 dark:hover:bg-success-900/40 transition-colors disabled:opacity-50"
          >
            {actionLoading === 'start' ? <RefreshCw className="w-3 h-3 animate-spin" /> : <Play className="w-3 h-3" />}
            Start
          </button>
        )}
      </div>
    </motion.div>
  );
};

const mockChartData = [
  { time: '00:00', queries: 120 },
  { time: '04:00', queries: 80 },
  { time: '08:00', queries: 250 },
  { time: '12:00', queries: 420 },
  { time: '16:00', queries: 380 },
  { time: '20:00', queries: 290 },
  { time: '24:00', queries: 180 },
];

export default function Dashboard() {
  const [stats, setStats] = useState({ zones: 0, records: 0, servers: 0, agents: 0 });
  const [servers, setServers] = useState([]);
  const [agents, setAgents] = useState([]);
  const [loading, setLoading] = useState(true);
  const [dnsRunning, setDnsRunning] = useState(false);
  const [dnsLoading, setDnsLoading] = useState(false);

  const loadData = async () => {
    setLoading(true);
    try {
      const [zonesRes, serversRes, agentsRes, dnsStatusRes] = await Promise.all([
        api.get('/api/v1/zones').catch(() => ({ data: [] })),
        api.get('/api/v1/servers').catch(() => ({ data: [] })),
        api.get('/api/v1/agents').catch(() => ({ data: [] })),
        api.get('/api/v1/dns/status').catch(() => ({ data: { servers: [] } }))
      ]);
      
      let recordCount = 0;
      const zones = zonesRes.data || [];
      for (const zone of zones.slice(0, 3)) {
        try {
          const recordsRes = await api.get(`/api/v1/zones/${zone.id}/records`);
          recordCount += (recordsRes.data?.length || 0);
        } catch (e) {
          console.warn('Failed to load records for zone:', zone.id, e);
        }
      }
      
      setStats({
        zones: zones.length,
        records: recordCount,
        servers: serversRes.data?.length || 0,
        agents: agentsRes.data?.length || 0,
      });
      
      setServers(serversRes.data || []);
      setAgents(agentsRes.data || []);
      setDnsRunning(dnsStatusRes.data?.servers?.length > 0);
    } catch (e) {
      console.warn('Failed to load dashboard data:', e);
    }
    setLoading(false);
  };

  useEffect(() => {
    const token = localStorage.getItem('token');
    if (token) {
      api.setToken(token);
    }
    loadData();
    
    const interval = setInterval(loadData, 30000);
    return () => clearInterval(interval);
  }, []);

  const handleStartDns = async () => {
    setDnsLoading(true);
    try {
      await api.post('/api/v1/dns/start', { bind: '0.0.0.0:53' });
      setDnsRunning(true);
    } catch (e) {
      console.error('Failed to start DNS:', e);
    }
    setDnsLoading(false);
  };

  const handleStopDns = async () => {
    setDnsLoading(true);
    try {
      await api.post('/api/v1/dns/stop', { id: 'main' });
      setDnsRunning(false);
    } catch (e) {
      console.error('Failed to stop DNS:', e);
    }
    setDnsLoading(false);
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <motion.div 
        initial={{ opacity: 0, y: -20 }}
        animate={{ opacity: 1, y: 0 }}
        className="flex flex-col md:flex-row md:items-center md:justify-between gap-4"
      >
        <div>
          <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Dashboard</h1>
          <p className="text-gray-500 dark:text-gray-400">Monitor your DNS infrastructure</p>
        </div>
        <div className="flex items-center gap-3">
          <button 
            onClick={loadData}
            disabled={loading}
            className="flex items-center gap-2 px-4 py-2 bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-xl text-sm font-medium text-gray-700 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
            Refresh
          </button>
          <button 
            onClick={dnsRunning ? handleStopDns : handleStartDns}
            disabled={dnsLoading}
            className={`flex items-center gap-2 px-4 py-2 rounded-xl text-sm font-medium text-white transition-all ${
              dnsRunning 
                ? 'bg-danger-500 hover:bg-danger-600' 
                : 'bg-success-500 hover:bg-success-600'
            } disabled:opacity-50`}
          >
            {dnsLoading ? (
              <RefreshCw className="w-4 h-4 animate-spin" />
            ) : dnsRunning ? (
              <><Square className="w-4 h-4" /> Stop DNS</>
            ) : (
              <><Play className="w-4 h-4" /> Start DNS</>
            )}
          </button>
        </div>
      </motion.div>

      {/* Stats Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard icon={Globe} label="Total Zones" value={stats.zones} color="primary" delay={0.1} />
        <StatCard icon={FileText} label="DNS Records" value={stats.records} color="success" delay={0.2} />
        <StatCard icon={Server} label="Servers" value={stats.servers} color="warning" delay={0.3} />
        <StatCard icon={Users} label="Agents" value={stats.agents} color="danger" delay={0.4} />
      </div>

      {/* Main Content Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Chart Section */}
        <motion.div 
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.5 }}
          className="lg:col-span-2 bg-white dark:bg-gray-800 rounded-2xl shadow-lg border border-gray-100 dark:border-gray-700 p-6"
        >
          <div className="flex items-center justify-between mb-6">
            <div>
              <h3 className="text-lg font-semibold text-gray-900 dark:text-white">DNS Queries</h3>
              <p className="text-sm text-gray-500 dark:text-gray-400">Last 24 hours</p>
            </div>
            <div className="flex items-center gap-2 px-3 py-1.5 bg-success-50 dark:bg-success-900/20 rounded-full">
              <TrendingUp className="w-4 h-4 text-success-600 dark:text-success-400" />
              <span className="text-sm font-medium text-success-600 dark:text-success-400">+12.5%</span>
            </div>
          </div>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={mockChartData}>
                <defs>
                  <linearGradient id="colorQueries" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#0ea5e9" stopOpacity={0.3}/>
                    <stop offset="95%" stopColor="#0ea5e9" stopOpacity={0}/>
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="#e5e7eb" />
                <XAxis dataKey="time" stroke="#9ca3af" fontSize={12} />
                <YAxis stroke="#9ca3af" fontSize={12} />
                <Tooltip 
                  contentStyle={{ 
                    backgroundColor: '#1f2937', 
                    border: 'none', 
                    borderRadius: '8px',
                    color: '#fff'
                  }}
                />
                <Area 
                  type="monotone" 
                  dataKey="queries" 
                  stroke="#0ea5e9" 
                  strokeWidth={2}
                  fillOpacity={1} 
                  fill="url(#colorQueries)" 
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </motion.div>

        {/* Quick Actions */}
        <motion.div 
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.6 }}
          className="bg-white dark:bg-gray-800 rounded-2xl shadow-lg border border-gray-100 dark:border-gray-700 p-6"
        >
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">Quick Actions</h3>
          <div className="space-y-3">
            <QuickAction icon={Globe} label="Manage Zones" description="Create & edit zones" to="/admin/zones" color="primary" delay={0.7} />
            <QuickAction icon={Server} label="DNS Servers" description="Configure servers" to="/admin/servers" color="warning" delay={0.8} />
            <QuickAction icon={Network} label="GeoDNS Rules" description="Geographic routing" to="/admin/georules" color="success" delay={0.9} />
            <QuickAction icon={Users} label="User Management" description="Manage users" to="/admin/users" color="primary" delay={1.0} />
          </div>
        </motion.div>
      </div>

      {/* Servers & Agents Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Servers */}
        <motion.div 
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.7 }}
          className="bg-white dark:bg-gray-800 rounded-2xl shadow-lg border border-gray-100 dark:border-gray-700 overflow-hidden"
        >
          <div className="p-6 border-b border-gray-100 dark:border-gray-700 flex items-center justify-between">
            <h3 className="text-lg font-semibold text-gray-900 dark:text-white">DNS Servers</h3>
            <Link to="/admin/servers" className="text-sm text-primary-600 hover:text-primary-500 font-medium">
              View all
            </Link>
          </div>
          <div className="p-6">
            {servers.length === 0 ? (
              <div className="text-center py-8">
                <Server className="w-12 h-12 text-gray-300 dark:text-gray-600 mx-auto mb-3" />
                <p className="text-gray-500 dark:text-gray-400">No servers configured</p>
                <Link to="/admin/servers" className="text-primary-600 hover:text-primary-500 text-sm font-medium mt-2 inline-block">
                  Add your first server
                </Link>
              </div>
            ) : (
              <div className="space-y-3">
                {servers.slice(0, 4).map((server) => (
                  <ServerCard 
                    key={server.id} 
                    server={server}
                    onStart={async (id) => await api.post('/api/v1/dns/start', { id, bind: '0.0.0.0:53' })}
                    onStop={async (id) => await api.post('/api/v1/dns/stop', { id })}
                    onRestart={async (id) => { await api.post('/api/v1/dns/stop', { id }); await api.post('/api/v1/dns/start', { id, bind: '0.0.0.0:53' }); }}
                    delay={0.8}
                  />
                ))}
              </div>
            )}
          </div>
        </motion.div>

        {/* Agents */}
        <motion.div 
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.8 }}
          className="bg-white dark:bg-gray-800 rounded-2xl shadow-lg border border-gray-100 dark:border-gray-700 overflow-hidden"
        >
          <div className="p-6 border-b border-gray-100 dark:border-gray-700 flex items-center justify-between">
            <h3 className="text-lg font-semibold text-gray-900 dark:text-white">Connected Agents</h3>
            <Link to="/admin/agents" className="text-sm text-primary-600 hover:text-primary-500 font-medium">
              View all
            </Link>
          </div>
          <div className="p-6">
            {agents.length === 0 ? (
              <div className="text-center py-8">
                <Activity className="w-12 h-12 text-gray-300 dark:text-gray-600 mx-auto mb-3" />
                <p className="text-gray-500 dark:text-gray-400">No agents connected</p>
                <Link to="/admin/agents" className="text-primary-600 hover:text-primary-500 text-sm font-medium mt-2 inline-block">
                  Learn about agents
                </Link>
              </div>
            ) : (
              <div className="space-y-3">
                {agents.slice(0, 4).map((agent) => (
                  <div key={agent.id} className="flex items-center justify-between p-3 rounded-xl bg-gray-50 dark:bg-gray-700/50">
                    <div className="flex items-center gap-3">
                      <div className={`w-2.5 h-2.5 rounded-full ${agent.online ? 'bg-success-500 animate-pulse' : 'bg-gray-300'}`}></div>
                      <div>
                        <p className="font-medium text-gray-900 dark:text-white">{agent.name}</p>
                        <p className="text-sm text-gray-500 dark:text-gray-400">{agent.addr}</p>
                      </div>
                    </div>
                    <span className={`px-2.5 py-1 rounded-full text-xs font-medium ${
                      agent.online 
                        ? 'bg-success-100 text-success-700 dark:bg-success-900/30 dark:text-success-400' 
                        : 'bg-gray-100 text-gray-600 dark:bg-gray-600 dark:text-gray-300'
                    }`}>
                      {agent.online ? 'Online' : 'Offline'}
                    </span>
                  </div>
                ))}
              </div>
            )}
          </div>
        </motion.div>
      </div>

      {/* System Status */}
      <motion.div 
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.9 }}
        className="bg-white dark:bg-gray-800 rounded-2xl shadow-lg border border-gray-100 dark:border-gray-700 p-6"
      >
        <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">System Status</h3>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          {[
            { name: 'API Server', status: 'healthy', icon: Server },
            { name: 'Database', status: 'healthy', icon: Database },
            { name: 'DNS Service', status: dnsRunning ? 'running' : 'stopped', icon: Network },
            { name: 'GeoDNS', status: 'ready', icon: Globe },
          ].map((item) => (
            <div key={item.name} className="flex items-center gap-3 p-3 rounded-xl bg-gray-50 dark:bg-gray-700/50">
              <div className={`w-8 h-8 rounded-lg flex items-center justify-center ${
                item.status === 'healthy' || item.status === 'running'
                  ? 'bg-success-100 dark:bg-success-900/30' 
                  : 'bg-warning-100 dark:bg-warning-900/30'
              }`}>
                <item.icon className={`w-4 h-4 ${
                  item.status === 'healthy' || item.status === 'running'
                    ? 'text-success-600 dark:text-success-400'
                    : 'text-warning-600 dark:text-warning-400'
                }`} />
              </div>
              <div>
                <p className="text-sm font-medium text-gray-900 dark:text-white">{item.name}</p>
                <p className={`text-xs ${
                  item.status === 'healthy' || item.status === 'running'
                    ? 'text-success-600 dark:text-success-400'
                    : 'text-warning-600 dark:text-warning-400'
                }`}>{item.status}</p>
              </div>
            </div>
          ))}
        </div>
      </motion.div>
    </div>
  );
}
