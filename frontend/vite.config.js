import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      '/auth': 'http://localhost:8000',
      '/analysis': 'http://localhost:8000',
      '/admin': 'http://localhost:8000',
      '/health': 'http://localhost:8000'
    }
  }
})
