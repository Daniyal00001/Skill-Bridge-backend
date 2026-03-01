import { Request, Response, NextFunction } from 'express'

/**
 * Custom request logger middleware to show clean, formatted logs in the terminal.
 * Masking sensitive data like passwords.
 */
export const requestLogger = (req: Request, res: Response, next: NextFunction) => {
  const timestamp = new Date().toLocaleTimeString()
  const method = req.method
  const url = req.originalUrl || req.url

  // Color coding for HTTP methods (basic ANSI codes)
  const colors: Record<string, string> = {
    GET: '\x1b[32m',    // Green
    POST: '\x1b[34m',   // Blue
    PUT: '\x1b[33m',    // Yellow
    DELETE: '\x1b[31m', // Red
    PATCH: '\x1b[35m',  // Magenta
    RESET: '\x1b[0m',
  }

  const methodColor = colors[method] || colors.RESET
  
  console.log(`\n[${timestamp}] ${methodColor}${method}${colors.RESET} ${url}`)

  // Helper to mask sensitive fields
  const maskSensitiveData = (data: any) => {
    if (!data || typeof data !== 'object') return data
    const masked = { ...data }
    const sensitiveFields = ['password', 'token', 'refreshToken', 'accessToken', 'secret']
    
    sensitiveFields.forEach(field => {
      if (masked[field]) {
        masked[field] = '********'
      }
    })
    return masked
  }

  // Log Inputs (Body, Query, Params)
  if (Object.keys(req.params).length > 0) {
    console.log(`  Params:`, JSON.stringify(req.params, null, 2))
  }
  if (Object.keys(req.query).length > 0) {
    console.log(`  Query :`, JSON.stringify(req.query, null, 2))
  }
  if (req.body && Object.keys(req.body).length > 0) {
    console.log(`  Body  :`, JSON.stringify(maskSensitiveData(req.body), null, 2))
  }

  next()
}
