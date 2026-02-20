import React from 'react'

const NotificationsContext = React.createContext()

export function NotificationsProvider({ children }){
  const [messages, setMessages] = React.useState([])
  const push = (msg) => setMessages(m => [...m, { id: Date.now(), text: msg, type: 'info' }])
  const remove = (id) => setMessages(m => m.filter(x=>x.id!==id))
  
  const notify = {
    push,
    success: (msg) => setMessages(m => [...m, { id: Date.now(), text: msg, type: 'success' }]),
    error: (msg) => setMessages(m => [...m, { id: Date.now(), text: msg, type: 'error' }]),
    warning: (msg) => setMessages(m => [...m, { id: Date.now(), text: msg, type: 'warning' }]),
  }
  
  return (
    <NotificationsContext.Provider value={notify}>
      {children}
      <div className="fixed bottom-4 right-4 space-y-2 z-50">
        {messages.map(m=> (
          <div key={m.id} className={`px-4 py-2 rounded shadow text-white ${
            m.type === 'success' ? 'bg-green-600' : 
            m.type === 'error' ? 'bg-red-600' : 
            m.type === 'warning' ? 'bg-yellow-600' : 'bg-gray-900'
          }`}>
            {m.text} 
            <button className="ml-2 opacity-70 hover:opacity-100" onClick={()=>remove(m.id)}>x</button>
          </div>
        ))}
      </div>
    </NotificationsContext.Provider>
  )
}

export default NotificationsContext
