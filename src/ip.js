import {
  convertIPv4ToBigInt,
  convertIPv6BigIntToString,
  convertIPv6ToBigInt,
  distinctRemoteAddr
} from './ipaddr.js'

/**
 * ### IPv4 and IPv6
 * - `*` match all
 *
 * ### IPv4
 * - `192.168.2.0` static
 * - `192.168.2.0/24` CIDR Notation
 *
 * ### IPv6
 * - `::1` static
 * - `::1/10` CIDR Notation
 */
const IS_CIDR_NOTATION_REGEX = /\/[0-9]{0,3}$/

function buildMatcher (rules) {
  const functionRules = []
  const staticRules = new Set()
  const cidrRules = [] // [isIPv4:boolean, addr:bigint, mask:bigint][]

  for (let rule of rules) {
    if (rule === '*') {
      return () => true
    } else if (typeof rule === 'function') {
      functionRules.push(rule)
    } else if (rule instanceof RegExp) {
      functionRules.push((ip) => rule.test(ip.addr))
    } else {
      if (IS_CIDR_NOTATION_REGEX.test(rule)) {
        const separatedRule = rule.split('/')

        const addrStr = separatedRule[0]
        const type = distinctRemoteAddr(addrStr)
        if (type === undefined) {
          throw new TypeError(`Invalid rule: ${rule}`)
        }

        const isIPv4 = type === 'IPv4'
        const prefix = parseInt(separatedRule[1])

        if (isIPv4 ? prefix === 32 : prefix === 128) {
          // this rule is a static rule
          rule = addrStr
        } else {
          const addr = (isIPv4 ? convertIPv4ToBigInt : convertIPv6ToBigInt)(addrStr)
          const mask = ((1n << BigInt(prefix)) - 1n) << BigInt((isIPv4 ? 32 : 128) - prefix)

          cidrRules.push([isIPv4, addr & mask, mask])
          continue
        }
      }

      const type = distinctRemoteAddr(rule)
      if (type === undefined) {
        throw new TypeError(`Invalid rule: ${rule}`)
      }
      staticRules.add(
        type === 'IPv4'
          ? rule // IPv4 address is already normalized, so it is registered as is.
          : convertIPv6BigIntToString(convertIPv6ToBigInt(rule)) // normalize IPv6 address (e.g. 0000:0000:0000:0000:0000:0000:0000:0001 => ::1)
      )
    }
  }

  return (remote) => {
    if (staticRules.has(remote.addr)) {
      return true
    }
    for (const [isIPv4, addr, mask] of cidrRules) {
      if (isIPv4 !== remote.isIPv4) {
        continue
      }
      const remoteAddr = (remote.binaryAddr ||= (
        isIPv4 ? convertIPv4ToBigInt : convertIPv6ToBigInt
      )(remote.addr))
      if ((remoteAddr & mask) === addr) {
        return true
      }
    }
    for (const rule of functionRules) {
      if (rule({ addr: remote.addr, type: remote.type })) {
        return true
      }
    }
    return false
  }
}

/**
 * IP restriction middleware for Hoa.
 *
 * @param {Object} options
 * @param {(ctx: HoaContext) => string} [options.getIp]
 * @param {Array<string|Function|RegExp>} [options.allowList]
 * @param {Array<string|Function|RegExp>} [options.denyList]
 * @param {(ctx: HoaContext) => void | Promise<void>} [options.denyHandler]
 * @returns {HoaMiddleware}
 */
export function ip (options = {}) {
  const {
    getIp = (ctx) => ctx.req.get('CF-Connecting-IP'),
    allowList = [],
    denyList = [],
    denyHandler = (ctx) => ctx.throw(403, 'Forbidden')
  } = options

  if (typeof getIp !== 'function') {
    throw new TypeError('getIp must be a function')
  }
  if (!Array.isArray(allowList)) {
    throw new TypeError('allowList must be an array')
  }
  if (!Array.isArray(denyList)) {
    throw new TypeError('denyList must be an array')
  }
  if (typeof denyHandler !== 'function') {
    throw new TypeError('denyHandler must be a function')
  }

  const allowLength = allowList.length
  const allowMatcher = buildMatcher(allowList)
  const denyMatcher = buildMatcher(denyList)

  return async function ipMiddleware (ctx, next) {
    const addr = getIp(ctx)
    if (!addr) {
      await denyHandler(ctx)
      return
    }

    const type = distinctRemoteAddr(addr)
    const remote = { addr, type, isIPv4: type === 'IPv4' }

    if (denyMatcher(remote)) {
      await denyHandler(ctx)
      return
    }

    if (allowLength === 0 || allowMatcher(remote)) {
      await next()
      return
    }

    await denyHandler(ctx)
  }
}

export default ip
