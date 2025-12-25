/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'

import * as challengeUtils from '../lib/challengeUtils'
import { challenges } from '../data/datacache'
import * as security from '../lib/insecurity'
import * as utils from '../lib/utils'

export function performRedirect () {
  return ({ query }: Request, res: Response, next: NextFunction) => {
    const toUrl: string = query.to as string

    // Validate URL to prevent open redirect vulnerability
    if (!isValidRedirectUrl(toUrl)) {
      res.status(400)
      next(new Error('Invalid redirect URL'))
      return
    }

    if (security.isRedirectAllowed(toUrl)) {
      challengeUtils.solveIf(challenges.redirectCryptoCurrencyChallenge, () => { return toUrl === 'https://explorer.dash.org/address/Xr556RzuwX6hg5EGpkybbv5RanJoZN17kW' || toUrl === 'https://blockchain.info/address/1AbKfgvw9psQ41NbLi8kufDQTezwG8DRZm' || toUrl === 'https://etherscan.io/address/0x0f933ab9fcaaa782d0279c300d73750e1311eae6' })
      challengeUtils.solveIf(challenges.redirectChallenge, () => { return isUnintendedRedirect(toUrl) })
      res.redirect(toUrl)
    } else {
      res.status(406)
      next(new Error('Unrecognized target URL for redirect: ' + toUrl))
    }
  }
}

function isUnintendedRedirect (toUrl: string) {
  let unintended = true
  for (const allowedUrl of security.redirectAllowlist) {
    unintended = unintended && !utils.startsWith(toUrl, allowedUrl)
  }
  return unintended
}

function isValidRedirectUrl (toUrl: string): boolean {
  if (!toUrl || typeof toUrl !== 'string') {
    return false
  }

  // Allow relative URLs (must start with / but not //)
  if (toUrl.startsWith('/') && !toUrl.startsWith('//')) {
    return true
  }

  // For absolute URLs, parse and validate the domain
  try {
    const url = new URL(toUrl)

    // Allowlist of trusted domains for redirects
    const allowedDomains = [
      'localhost',
      '127.0.0.1',
      // Add other trusted domains as needed
    ]

    // Extract hostname without port
    const hostname = url.hostname.toLowerCase()

    // Check if domain is in allowlist
    for (const domain of allowedDomains) {
      if (hostname === domain || hostname.endsWith('.' + domain)) {
        return true
      }
    }

    // Reject external domains not in allowlist
    return false
  } catch (e) {
    // Invalid URL format
    return false
  }
}
