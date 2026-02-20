import React from 'react'
import api from '../api/client'

export default function BulkImport({ endpoint, onComplete, accept='text/csv,application/json' }){
  const [file, setFile] = React.useState(null)
  const [loading, setLoading] = React.useState(false)

  const parseCSV = (text) => {
    const lines = text.trim().split(/\r?\n/)
    const headers = lines[0].split(',').map(h=>h.trim())
    return lines.slice(1).map(l => {
      const cols = l.split(',').map(c=>c.trim())
      const obj = {}
      headers.forEach((h,i)=> obj[h]=cols[i])
      return obj
    })
  }

  const submit = async ()=>{
    if (!file) return alert('Select a file')
    setLoading(true)
    try {
      const text = await file.text()
      let payload = null
      if (file.type === 'application/json' || file.name.endsWith('.json')) payload = JSON.parse(text)
      else payload = parseCSV(text)

      await api.post(endpoint, payload)
      onComplete && onComplete()
    } catch (e) { console.error(e); alert('Import failed') }
    setLoading(false)
  }

  return (
    <div className="p-2 border rounded bg-gray-50">
      <input type="file" accept={accept} onChange={e=>setFile(e.target.files[0])} />
      <div className="mt-2">
        <button className="bg-blue-600 text-white px-3 py-1 rounded" onClick={submit} disabled={loading}>{loading ? 'Importing...' : 'Import'}</button>
      </div>
    </div>
  )
}
