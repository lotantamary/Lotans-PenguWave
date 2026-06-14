import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      // Forward API calls to the backend so the browser talks same-origin
      // (the httpOnly session cookie just works, no CORS needed).
      '/api': 'http://localhost:3001',
    },
  },
})
