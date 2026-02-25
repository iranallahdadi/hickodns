import React from 'react'
import api from '../../api/client'
import { Link } from 'react-router-dom'
import BulkImport from '../../components/BulkImport'
import Notifications from '../../components/Notifications'
import { useFormValidation, validators, FormField, downloadTemplate } from '../../hooks/useFormValidation'
import { usePagination, useTableSort, useAdvancedSearch, PaginationControls, SortableHeader, FadeIn, SkeletonTable } from '../../hooks/useAdvancedUI'

export default function Zones(){
  const [zones, setZones] = React.useState([])
  const [loading, setLoading] = React.useState(false)
  const notify = React.useContext(Notifications)
  const { values, errors, bind, validate, reset } = useFormValidation(
    { domain: '' },
    (vals) => ({ domain: validators.domain(vals.domain) })
  )
  const [editingZone, setEditingZone] = React.useState(null)
  const [editDomain, setEditDomain] = React.useState('')
  const [editType, setEditType] = React.useState('primary')

  // Advanced search with debouncing
  const { searchTerm, filteredItems, handleSearch } = useAdvancedSearch(
    zones,
    ['domain', 'id']
  )
  
  // Table sorting
  const { sortedItems, sortConfig, requestSort } = useTableSort(filteredItems, { field: 'domain', order: 'asc' })
  
  // Pagination
  const pagination = usePagination(sortedItems, 10)

  const load = async () => { 
    setLoading(true)
    try { 
      const r = await api.get('/api/v1/zones')
      setZones(r.data || []) 
    } catch (e) { 
      console.error('Error loading zones', e)
      notify?.error('Failed to load zones')
    } finally {
      setLoading(false)
    }
  }

  React.useEffect(()=>{ 
    const token = localStorage.getItem('token')
    if (token) api.setToken(token)
    load()
  }, [])

  const create = async () => { 
    if (!validate()) return
    try { 
      await api.post('/api/v1/zones', { domain: values.domain })
      reset()
      load()
      notify?.success(`Zone ${values.domain} created`)
    } catch (e) { 
      notify?.error('Error creating zone')
    } 
  }
  
  const startEdit = (zone) => {
    setEditingZone(zone)
    setEditDomain(zone.domain)
    setEditType(zone.zone_type || 'primary')
  }

  const cancelEdit = () => {
    setEditingZone(null)
    setEditDomain('')
    setEditType('primary')
  }

  const saveEdit = async () => {
    if (!editDomain || validators.domain(editDomain)) {
      notify?.error('Invalid domain')
      return
    }
    try {
      await api.put(`/api/v1/zones/${editingZone.id}`, { domain: editDomain, zone_type: editType })
      notify?.success('Zone updated')
      cancelEdit()
      load()
    } catch (e) {
      notify?.error('Error updating zone')
    }
  }

  const deleteZone = async (zone) => {
    if (!window.confirm(`Delete zone ${zone.domain}?`)) return
    try {
      await api.delete(`/api/v1/zones/${zone.id}`)
      notify?.success('Zone deleted')
      if (editingZone && editingZone.id === zone.id) cancelEdit()
      load()
    } catch (e) {
      notify?.error('Error deleting zone')
    }
  }

  const onBulkComplete = () => { load(); notify?.success('Zones imported'); }

  return (
    <div className="bg-white dark:bg-gray-800 shadow rounded p-6">
      <div className="mb-6">
        <h3 className="text-lg font-semibold mb-4">Zones</h3>
        {!editingZone ? (
          <div className="grid gap-2 mb-4 max-w-md">
            <FormField label="Domain" error={errors.domain}>
              <input className="w-full border dark:border-gray-600 dark:bg-gray-700 dark:text-white rounded px-3 py-2" placeholder="example.com" {...bind('domain')} />
            </FormField>
            <div className="flex items-center space-x-2">
              <button className="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded transition-colors" onClick={create}>Create Zone</button>
              <BulkImport endpoint={'/api/v1/zones/bulk'} onComplete={onBulkComplete} />
              <button className="text-sm text-gray-600 dark:text-gray-400 hover:underline" onClick={() => downloadTemplate('zones_template.csv', ['domain'], [['example.com'], ['test.io']])}>Template</button>
            </div>
          </div>
        ) : (
          <div className="grid gap-2 mb-4 max-w-md">
            <FormField label="Domain">
              <input className="w-full border dark:border-gray-600 dark:bg-gray-700 dark:text-white rounded px-3 py-2" value={editDomain} onChange={e=>setEditDomain(e.target.value)} />
            </FormField>
            <FormField label="Zone Type">
              <select className="w-full border dark:border-gray-600 dark:bg-gray-700 dark:text-white rounded px-3 py-2" value={editType} onChange={e=>setEditType(e.target.value)}>
                <option value="primary">primary</option>
                <option value="secondary">secondary</option>
              </select>
            </FormField>
            <div className="flex items-center space-x-2">
              <button className="bg-green-600 hover:bg-green-700 text-white px-4 py-2 rounded" onClick={saveEdit}>Save</button>
              <button className="bg-gray-300 hover:bg-gray-400 text-gray-800 px-4 py-2 rounded" onClick={cancelEdit}>Cancel</button>
            </div>
          </div>
        )}
      </div>

      {/* Advanced Search */}
      <div className="mb-4">
        <input
          type="text"
          placeholder="Search zones by domain or ID..."
          value={searchTerm}
          onChange={(e) => handleSearch(e.target.value)}
          className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent dark:bg-gray-700 dark:border-gray-600 dark:text-white dark:placeholder-gray-400 transition-all"
        />
        {filteredItems.length > 0 && (
          <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">
            Found {filteredItems.length} zone{filteredItems.length !== 1 ? 's' : ''}
          </p>
        )}
      </div>

      {/* Table */}
      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="bg-gray-50 dark:bg-gray-700 border-b dark:border-gray-600">
              <SortableHeader 
                field="domain" 
                label="Domain" 
                sortConfig={sortConfig} 
                onSort={requestSort}
              />
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-700 dark:text-gray-300 uppercase tracking-wider">Created</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-700 dark:text-gray-300 uppercase tracking-wider">Type</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-700 dark:text-gray-300 uppercase tracking-wider">Actions</th>
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <SkeletonTable rows={5} columns={4} />
            ) : pagination.currentItems.length > 0 ? (
              pagination.currentItems.map(z => (
                <FadeIn key={z.id}>
                  <tr className="border-b dark:border-gray-700 hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors">
                    <td className="px-6 py-4 whitespace-nowrap text-gray-900 dark:text-gray-100">{z.domain}</td>
                    <td className="px-6 py-4 whitespace-nowrap text-xs text-gray-500 dark:text-gray-400">
                      {z.created_at ? new Date(z.created_at).toLocaleDateString() : 'N/A'}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">{z.zone_type || 'primary'}</td>
                    <td className="px-6 py-4 whitespace-nowrap space-x-2">
                      <Link to={`/admin/zones/${z.id}/records`} className="text-blue-600 dark:text-blue-400 hover:underline font-medium">
                        Manage Records
                      </Link>
                      <button onClick={()=>startEdit(z)} className="text-green-600 hover:text-green-800">Edit</button>
                      <button onClick={()=>deleteZone(z)} className="text-red-600 hover:text-red-800">Delete</button>
                    </td>
                  </tr>
                </FadeIn>
              ))
            ) : (
              <tr>
                <td colSpan="3" className="px-6 py-4 text-center text-gray-500 dark:text-gray-400">
                  No zones found
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      {/* Pagination */}
      <PaginationControls pagination={pagination} />
    </div>
  )
}
