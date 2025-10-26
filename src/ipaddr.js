const IPV4_REGEX = /^[0-9]{0,3}\.[0-9]{0,3}\.[0-9]{0,3}\.[0-9]{0,3}$/

/**
 * Expand IPv6 Address
 * @param ipV6 Shorten IPv6 Address
 * @return expanded IPv6 Address
 */
export const expandIPv6 = (ipV6) => {
  const sections = ipV6.split(':')
  if (IPV4_REGEX.test(sections.at(-1))) {
    sections.splice(
      -1,
      1,
      ...convertIPv6BigIntToString(convertIPv4ToBigInt(sections.at(-1))) // => ::7f00:0001
        .substring(2) // => 7f00:0001
        .split(':') // => ['7f00', '0001']
    )
  }
  for (let i = 0; i < sections.length; i++) {
    const node = sections[i]
    if (node !== '') {
      sections[i] = node.padStart(4, '0')
    } else {
      sections[i + 1] === '' && sections.splice(i + 1, 1)
      sections[i] = new Array(8 - sections.length + 1).fill('0000').join(':')
    }
  }
  return sections.join(':')
}

/**
 * Distinct Remote Addr
 * @param remoteAddr Remote Addr
 */
export const distinctRemoteAddr = (remoteAddr) => {
  if (IPV4_REGEX.test(remoteAddr)) {
    return 'IPv4'
  }
  if (remoteAddr.includes(':')) {
    // Domain can't include `:`
    return 'IPv6'
  }
}

/**
 * Convert IPv4 to BigInt
 * @param ipv4 IPv4 Address
 * @returns BigInt
 */
export const convertIPv4ToBigInt = (ipv4) => {
  const parts = ipv4.split('.')
  let result = 0n
  for (let i = 0; i < 4; i++) {
    result <<= 8n
    result += BigInt(parts[i])
  }
  return result
}

/**
 * Convert IPv6 to BigInt
 * @param ipv6 IPv6 Address
 * @returns BigInt
 */
export const convertIPv6ToBigInt = (ipv6) => {
  const sections = expandIPv6(ipv6).split(':')
  let result = 0n
  for (let i = 0; i < 8; i++) {
    result <<= 16n
    result += BigInt(parseInt(sections[i], 16))
  }
  return result
}

/**
 * Convert a BigInt IPv4 address to a dotted string.
 * @param ipV4 IPv4 as BigInt
 * @return IPv4 Address in string
 */
export const convertIPv4BigIntToString = (ipV4) => {
  const sections = []
  for (let i = 0; i < 4; i++) {
    sections.push((ipV4 >> BigInt(8 * (3 - i))) & 0xffn)
  }
  return sections.join('.')
}

/**
 * Convert a BigInt IPv6 address to a compressed string.
 * @param ipV6 IPv6 as BigInt
 * @return normalized IPv6 Address in string
 */
export const convertIPv6BigIntToString = (ipV6) => {
  // IPv6-mapped IPv4 address
  if (ipV6 >> 32n === 0xffffn) {
    return `::ffff:${convertIPv4BigIntToString(ipV6 & 0xffffffffn)}`
  }

  const sections = []
  for (let i = 0; i < 8; i++) {
    sections.push(((ipV6 >> BigInt(16 * (7 - i))) & 0xffffn).toString(16))
  }

  let currentZeroStart = -1
  let maxZeroStart = -1
  let maxZeroEnd = -1
  for (let i = 0; i < 8; i++) {
    if (sections[i] === '0') {
      if (currentZeroStart === -1) {
        currentZeroStart = i
      }
    } else {
      if (currentZeroStart > -1) {
        if (i - currentZeroStart > maxZeroEnd - maxZeroStart) {
          maxZeroStart = currentZeroStart
          maxZeroEnd = i
        }
        currentZeroStart = -1
      }
    }
  }
  if (currentZeroStart > -1) {
    if (8 - currentZeroStart > maxZeroEnd - maxZeroStart) {
      maxZeroStart = currentZeroStart
      maxZeroEnd = 8
    }
  }
  if (maxZeroStart !== -1) {
    sections.splice(maxZeroStart, maxZeroEnd - maxZeroStart, ':')
  }

  return sections.join(':').replace(/:{2,}/g, '::')
}
