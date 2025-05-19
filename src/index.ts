import { Elysia, env } from 'elysia'
import { cors } from '@elysiajs/cors'
import { swagger } from '@elysiajs/swagger'
import { authRoutes } from '@routes/auth-routes'

// Buat konfigurasi CORS
const corsConfig = cors({
  origin: 'http://localhost:12202',
  credentials: true,
  allowedHeaders: ['Content-Type', 'Authorization'],
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH']
})

// Inisialisasi app
const app = new Elysia()
  .use(swagger()) 
  .use(corsConfig)
  .group('/api/v1', (app) =>
    app.use(authRoutes)
  )



// Menyalakan server dan log hostname/port
app.listen(env.PORT ?? 3000, ({ hostname, port }) => {
  console.log(`🦊 Elysia is running at http://${hostname}:${port}`)
})
