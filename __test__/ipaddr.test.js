import {
  convertIPv4BigIntToString,
  convertIPv4ToBigInt,
  convertIPv6BigIntToString,
  convertIPv6ToBigInt,
  distinctRemoteAddr,
  expandIPv6,
} from '../src/ipaddr.js'

describe('expandIPv6', () => {
  it('Should expand IPv6 addresses correctly', () => {
    expect(expandIPv6('1::1')).toBe('0001:0000:0000:0000:0000:0000:0000:0001')
    expect(expandIPv6('::1')).toBe('0000:0000:0000:0000:0000:0000:0000:0001')
    expect(expandIPv6('2001:2::')).toBe('2001:0002:0000:0000:0000:0000:0000:0000')
    expect(expandIPv6('2001:0:0:db8::1')).toBe('2001:0000:0000:0db8:0000:0000:0000:0001')
    expect(expandIPv6('::ffff:127.0.0.1')).toBe('0000:0000:0000:0000:0000:ffff:7f00:0001')
  })
})
describe('distinctRemoteAddr', () => {
  it('Should distinguish IP address types correctly', () => {
    expect(distinctRemoteAddr('1::1')).toBe('IPv6')
    expect(distinctRemoteAddr('::1')).toBe('IPv6')
    expect(distinctRemoteAddr('::ffff:127.0.0.1')).toBe('IPv6')
    expect(distinctRemoteAddr('192.168.2.0')).toBe('IPv4')
    expect(distinctRemoteAddr('example.com')).toBeUndefined()
  })
})

describe('convertIPv4ToBigInt', () => {
  it('Should result is valid', () => {
    expect(convertIPv4ToBigInt('0.0.0.0')).toBe(0n)
    expect(convertIPv4ToBigInt('0.0.0.1')).toBe(1n)

    expect(convertIPv4ToBigInt('0.0.1.0')).toBe(1n << 8n)
  })
})

describe('convertIPv4ToString', () => {
  // add tons of test cases here
  test.each`
    input        | expected
    ${'0.0.0.0'} | ${'0.0.0.0'}
    ${'0.0.0.1'} | ${'0.0.0.1'}
    ${'0.0.1.0'} | ${'0.0.1.0'}
  `('convertIPv4ToString($input) === $expected', ({ input, expected }) => {
    expect(convertIPv4BigIntToString(convertIPv4ToBigInt(input))).toBe(expected)
  })
})

describe('convertIPv6ToBigInt', () => {
  it('Should result is valid', () => {
    expect(convertIPv6ToBigInt('::0')).toBe(0n)
    expect(convertIPv6ToBigInt('::1')).toBe(1n)

    expect(convertIPv6ToBigInt('::f')).toBe(15n)
    expect(convertIPv6ToBigInt('1234:::5678')).toBe(24196103360772296748952112894165669496n)
    expect(convertIPv6ToBigInt('::ffff:127.0.0.1')).toBe(281472812449793n)
  })
})

describe('convertIPv6ToString', () => {
  // add tons of test cases here
  test.each`
    input                                        | expected
    ${'::1'}                                     | ${'::1'}
    ${'1::'}                                     | ${'1::'}
    ${'1234:::5678'}                             | ${'1234::5678'}
    ${'2001:2::'}                                | ${'2001:2::'}
    ${'2001::db8:0:0:0:0:1'}                     | ${'2001:0:db8::1'}
    ${'1234:5678:9abc:def0:1234:5678:9abc:def0'} | ${'1234:5678:9abc:def0:1234:5678:9abc:def0'}
    ${'::ffff:127.0.0.1'}                        | ${'::ffff:127.0.0.1'}
  `('convertIPv6ToString($input) === $expected', ({ input, expected }) => {
    expect(convertIPv6BigIntToString(convertIPv6ToBigInt(input))).toBe(expected)
  })
})

describe('IPv6 zero-compression', () => {
  it('should compress longest zero run in the middle', () => {
    expect(convertIPv6BigIntToString(convertIPv6ToBigInt('1:0:0:0:0:0:0:1'))).toBe('1::1')
  })

  it('should compress trailing zero run', () => {
    expect(convertIPv6BigIntToString(convertIPv6ToBigInt('1:1:0:0:0:0:0:0'))).toBe('1:1::')
  })

  it('should choose longest among multiple zero runs', () => {
    expect(convertIPv6BigIntToString(convertIPv6ToBigInt('0:0:0:1:0:0:0:0'))).toBe('0:0:0:1::')
    expect(convertIPv6BigIntToString(convertIPv6ToBigInt('1:0:0:1:0:0:0:1'))).toBe('1:0:0:1::1')
  })

  it('should keep earlier run when runs have equal length', () => {
    expect(convertIPv6BigIntToString(convertIPv6ToBigInt('1:0:0:1:0:0:1:1'))).toBe('1::1:0:0:1:1')
    expect(convertIPv6BigIntToString(convertIPv6ToBigInt('1:0:0:1:0:0:1:0'))).toBe('1::1:0:0:1:0')
  })
})
