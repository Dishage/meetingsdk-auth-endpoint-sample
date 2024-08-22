import cors from 'cors'
import dotenv from 'dotenv'
import express from 'express'
import { KJUR } from 'jsrsasign'
import { inNumberArray, isBetween, isRequiredAllOrNone, validateRequest } from './validations.js'
import { kv } from '@vercel/kv'
import { Ratelimit } from '@upstash/ratelimit'

dotenv.config()
const app = express()

// Create a new ratelimiter, that allows 15 requests per 10 seconds
const ratelimit = new Ratelimit({
  redis: kv,
  limiter: Ratelimit.slidingWindow(15, '10s')
})

// CORS configuration
const corsOptions = {
  origin: ['https://staff.elitetuition.com.au'], // Add other allowed origins if needed
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'X-API-Key'],
  credentials: true,
  optionsSuccessStatus: 204
}

// Apply CORS middleware
app.use(cors(corsOptions))

// Handle preflight requests
app.options('*', cors(corsOptions))

app.use(express.json())

// Rate limiting middleware
const rateLimitMiddleware = async (req, res, next) => {
  const identifier = req.ip ?? '127.0.0.1'
  const result = await ratelimit.limit(identifier)

  if (!result.success) {
    console.log(`Rate limit exceeded for ${identifier} IP Address: ${identifier}`)
    // Offload the fetch request to a serverless function or background worker instead
    try {
      await fetch(
        'https://discord.com/api/webhooks/1189011490733301781/xC9ZriwRbrH9oE7vcswSLQ0ekks7cdE29st-dlFQHQikX8tSki0SV-B4N_J80Nz4Bc4-',
        {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({
            content: `Limit triggered for: ${request.url} IP Address: ${identifier}`,
            username: 'IP Bot'
          })
        }
      )
    } catch (error) {
      console.error('Failed to send webhook:', error)
    }
    return res.status(429).json({
      success: false,
      message: 'Rate limit exceeded'
    })
  }

  next()
}

app.use(rateLimitMiddleware)

const propValidations = {
  role: inNumberArray([0, 1]),
  expirationSeconds: isBetween(1800, 172800)
}
const schemaValidations = [isRequiredAllOrNone(['meetingNumber', 'role'])]

const coerceRequestBody = (body) => ({
  ...body,
  ...['role', 'expirationSeconds'].reduce(
    (acc, cur) => ({ ...acc, [cur]: typeof body[cur] === 'string' ? parseInt(body[cur]) : body[cur] }),
    {}
  )
})

// Middleware to check for API key
const checkApiKey = (req, res, next) => {
  const apiKey = req.get('X-API-Key')
  if (!apiKey || apiKey !== process.env.API_KEY) {
    return res.status(401).json({ error: 'Invalid or missing API key' })
  }
  next()
}

app.post('/', checkApiKey, (req, res) => {
  const requestBody = coerceRequestBody(req.body)
  const validationErrors = validateRequest(requestBody, propValidations, schemaValidations)
  if (validationErrors.length > 0) {
    return res.status(400).json({ errors: validationErrors })
  }
  const { meetingNumber, role, expirationSeconds } = requestBody
  const iat = Math.floor(Date.now() / 1000)
  const exp = expirationSeconds ? iat + expirationSeconds : iat + 60 * 60 * 2
  const oHeader = { alg: 'HS256', typ: 'JWT' }
  const oPayload = {
    appKey: process.env.ZOOM_MEETING_SDK_KEY,
    sdkKey: process.env.ZOOM_MEETING_SDK_KEY,
    mn: meetingNumber,
    role,
    iat,
    exp,
    tokenExp: exp
  }
  const sHeader = JSON.stringify(oHeader)
  const sPayload = JSON.stringify(oPayload)
  const sdkJWT = KJUR.jws.JWS.sign('HS256', sHeader, sPayload, process.env.ZOOM_MEETING_SDK_SECRET)
  return res.json({ signature: sdkJWT })
})

// Only use app.listen in development, not on Vercel
if (process.env.NODE_ENV !== 'production') {
  const port = process.env.PORT || 4000
  app.listen(port, () => {
    console.log(`Zoom Meeting SDK Auth Endpoint Sample Node.js, listening on port ${port}!`)
  })
}

export default app
