import React from 'react'
import ReactDOM from 'react-dom/client'
import '@fontsource-variable/inter'
import '@fontsource-variable/jetbrains-mono'
import './styles.css'
import './operator.css'
import App from './App'

// Opened in a plain browser rather than Electron: install a fake bridge so the
// UI can be worked on without a database. `import.meta.env.DEV` is statically
// false in a production build, so Vite drops this branch and devMock entirely.
if (import.meta.env.DEV && !window.opentable) {
  const { installDevMock } = await import('./devMock')
  installDevMock()
}

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
)
