import type { HoaContext, HoaMiddleware } from 'hoa'

export type IPType = 'IPv4' | 'IPv6'

export interface RemoteInfo {
  addr: string
  type: IPType
}

export type IPRule = string | RegExp | ((remote: RemoteInfo) => boolean)

export interface IPOptions {
  /**
   * Resolve client IP address from context; defaults to reading 'CF-Connecting-IP' header.
   */
  getIp?: (ctx: HoaContext) => string | null | undefined
  /**
   * Allow rules: string (static or CIDR), RegExp, or function(remote) => boolean.
   */
  allowList?: IPRule[]
  /**
   * Deny rules: string (static or CIDR), RegExp, or function(remote) => boolean.
   */
  denyList?: IPRule[]
  /**
   * Handler invoked when denied; may set response or throw.
   */
  denyHandler?: (ctx: HoaContext) => void | Promise<void>
}

/**
 * IP restriction middleware for Hoa.
 */
export function ip(options?: IPOptions): HoaMiddleware

export default ip