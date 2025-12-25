/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import path from 'node:path'
import { type Request, type Response, type NextFunction } from 'express'

export function serveLogFiles () {
  return ({ params }: Request, res: Response, next: NextFunction) => {
    const file = params.file

    // Canonicalize the logs directory to absolute path
    const logsDir = path.resolve('logs/')
    // Resolve the requested file path
    const requestedPath = path.resolve(logsDir, file)

    // Validate that the resolved path stays within the logs directory
    if (!requestedPath.startsWith(logsDir + path.sep) && requestedPath !== logsDir) {
      res.status(403)
      next(new Error('Access denied: Path traversal detected'))
    } else {
      res.sendFile(requestedPath)
    }
  }
}
