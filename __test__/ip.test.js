import { Hoa } from 'hoa'
import { ip } from '../src/ip.js'

describe('ip middleware', () => {
  it('Should restrict', async () => {
    const app = new Hoa()

    app.use(
      ip({
        getIp: (ctx) => ctx.req.get('CF-Connecting-IP'),
        allowList: ['192.168.1.0', '192.168.2.0/24'],
        denyList: ['192.168.2.10']
      })
    )

    app.use(async (ctx) => {
      ctx.res.body = 'Hello World!'
    })

    const mockRequest = (ipaddr) => new Request('http://localhost/basic', { headers: { 'CF-Connecting-IP': ipaddr } })

    expect((await app.fetch(mockRequest('0.0.0.0'))).status).toBe(403)
    expect((await app.fetch(mockRequest('192.168.1.0'))).status).toBe(200)
    expect((await app.fetch(mockRequest('192.168.2.5'))).status).toBe(200)
    expect((await app.fetch(mockRequest('192.168.2.10'))).status).toBe(403)
  })

  it('Should work when allowList is empty', async () => {
    const app = new Hoa()

    app.use(
      ip({
        getIp: (ctx) => ctx.req.get('CF-Connecting-IP'),
        denyList: ['192.168.1.0']
      })
    )

    app.use(async (ctx) => {
      ctx.res.body = 'Hello World!'
    })

    const mockRequest = (ipaddr) => new Request('http://localhost/allow-empty', { headers: { 'CF-Connecting-IP': ipaddr } })

    expect((await app.fetch(mockRequest('0.0.0.0'))).status).toBe(200)
    expect((await app.fetch(mockRequest('192.168.1.0'))).status).toBe(403)
    expect((await app.fetch(mockRequest('192.168.2.5'))).status).toBe(200)
    expect((await app.fetch(mockRequest('192.168.2.10'))).status).toBe(200)
  })

  it('allowList with * matches all and allows request', async () => {
    const app = new Hoa()

    app.use(
      ip({
        allowList: ['*']
      })
    )

    app.use(async (ctx) => {
      ctx.res.body = 'OK'
    })

    const res = await app.fetch(new Request('http://localhost/allow-all', {
      headers: { 'CF-Connecting-IP': '203.0.113.5' }
    }))
    expect(res.status).toBe(200)
  })

  it('Supports RegExp in allowList and denyList', async () => {
    const app = new Hoa()

    app.use(
      ip({
        getIp: (ctx) => ctx.req.get('CF-Connecting-IP'),
        allowList: [/^8\.8\.8\.[0-3]$/],
        denyList: [/^8\.8\.8\.2$/]
      })
    )

    app.use(async (ctx) => {
      ctx.res.body = 'Hello Regex!'
    })

    const mockRequest = (ipaddr) => new Request('http://localhost/regex', { headers: { 'CF-Connecting-IP': ipaddr } })

    expect((await app.fetch(mockRequest('1.1.1.1'))).status).toBe(403)
    expect((await app.fetch(mockRequest('8.8.8.1'))).status).toBe(200)
    expect((await app.fetch(mockRequest('8.8.8.2'))).status).toBe(403)
    expect((await app.fetch(mockRequest('8.8.8.4'))).status).toBe(403)
  })

  it('Custom denyHandler', async () => {
    const app = new Hoa()

    app.use(
      ip({
        getIp: () => '0.0.0.0',
        denyList: ['0.0.0.0'],
        denyHandler: (ctx) => {
          ctx.res.body = 'error'
        }
      })
    )

    app.use(async (ctx) => {
      ctx.res.body = 'Hello, Hoa!'
    })

    const response = await app.fetch(new Request('http://localhost/'))
    expect(await response.text()).toBe('error')
  })

  describe('Missing IP handling', () => {
    it('calls custom denyHandler when IP is missing', async () => {
      const app = new Hoa()

      app.use(
        ip({
          getIp: () => undefined,
          denyHandler: (ctx) => {
            ctx.res.status = 418
            ctx.res.body = 'noip'
          }
        })
      )

      app.use(async (ctx) => {
        ctx.res.body = 'never reached'
      })

      const res = await app.fetch(new Request('http://localhost/no-ip'))
      expect(res.status).toBe(418)
      expect(await res.text()).toBe('noip')
    })

    it('returns 403 with default denyHandler when IP is undefined', async () => {
      const app = new Hoa()
      app.use(ip({ getIp: () => undefined }))
      app.use(async (ctx) => { ctx.res.body = 'never' })

      const res = await app.fetch(new Request('http://localhost/no-ip-default'))
      expect(res.status).toBe(403)
    })

    it('returns 403 when IP is undefined and denyHandler is null', async () => {
      const app = new Hoa()
      app.use(ip({ getIp: () => undefined, denyHandler: null }))
      app.use(async (ctx) => { ctx.res.body = 'never' })

      const res = await app.fetch(new Request('http://localhost/no-ip-throw'))
      expect(res.status).toBe(403)
    })

    it('returns 403 when IP is empty string and denyHandler is non-function', async () => {
      const app = new Hoa()
      app.use(ip({ getIp: () => '', denyHandler: 0 }))
      app.use(async (ctx) => { ctx.res.body = 'never' })

      const res = await app.fetch(new Request('http://localhost/no-ip-empty'))
      expect(res.status).toBe(403)
    })
  })

  it('CIDR mixed types continue and cache binaryAddr', async () => {
    const app = new Hoa()

    app.use(
      ip({
        getIp: (ctx) => ctx.req.get('CF-Connecting-IP'),
        allowList: ['::0/1', '192.168.2.0/25', '192.168.2.128/25']
      })
    )

    app.use(async (ctx) => {
      ctx.res.body = 'OK'
    })

    const req = new Request('http://localhost/cidr-mixed', { headers: { 'CF-Connecting-IP': '192.168.2.130' } })
    const res = await app.fetch(req)
    expect(res.status).toBe(200)
  })

  it('CIDR rule with different IP version is skipped', async () => {
    const app = new Hoa()

    app.use(
      ip({
        getIp: (ctx) => ctx.req.get('CF-Connecting-IP'),
        allowList: ['::0/1']
      })
    )

    app.use(async (ctx) => {
      ctx.res.body = 'OK'
    })

    const res = await app.fetch(new Request('http://localhost/skip', { headers: { 'CF-Connecting-IP': '192.168.2.1' } }))
    expect(res.status).toBe(403)
  })

  it('Invalid rules throw TypeError', () => {
    expect(() => ip({ allowList: ['x.x.x.x/24'] })).toThrow(TypeError)
    expect(() => ip({ denyList: ['not-an-ip'] })).toThrow(TypeError)
  })

  it('getIp must be a function', () => {
    expect(() => ip({ getIp: 123 })).toThrow('getIp must be a function')
  })

  it('uses default getIp from CF-Connecting-IP header', async () => {
    const app = new Hoa()

    app.use(ip())

    app.use(async (ctx) => {
      ctx.res.body = 'OK'
    })

    const res = await app.fetch(new Request('http://localhost/default-getip', {
      headers: { 'CF-Connecting-IP': '8.8.8.8' }
    }))
    expect(res.status).toBe(200)
  })

  it('allowList must be an array', () => {
    expect(() => ip({ allowList: '127.0.0.1' })).toThrow('allowList must be an array')
  })

  it('denyList must be an array', () => {
    expect(() => ip({ denyList: '127.0.0.1' })).toThrow('denyList must be an array')
  })
})

describe('isMatchForRule', () => {
  const isMatch = async (info, rule) => {
    const app = new Hoa()

    app.use(
      ip({
        getIp: () => info.addr,
        allowList: [rule]
      })
    )

    app.use(async (ctx) => {
      ctx.res.body = 'OK'
    })

    const res = await app.fetch(new Request('http://localhost/'))
    return res.status === 200
  }

  it('star', async () => {
    expect(await isMatch({ addr: '192.168.2.0', type: 'IPv4' }, '*')).toBeTruthy()
    expect(await isMatch({ addr: '192.168.2.1', type: 'IPv4' }, '*')).toBeTruthy()
    expect(await isMatch({ addr: '::0', type: 'IPv6' }, '*')).toBeTruthy()
  })

  it('CIDR Notation', async () => {
    expect(await isMatch({ addr: '192.168.2.0', type: 'IPv4' }, '192.168.2.0/24')).toBeTruthy()
    expect(await isMatch({ addr: '192.168.2.1', type: 'IPv4' }, '192.168.2.0/24')).toBeTruthy()
    expect(await isMatch({ addr: '192.168.2.1', type: 'IPv4' }, '192.168.2.1/32')).toBeTruthy()
    expect(await isMatch({ addr: '192.168.2.1', type: 'IPv4' }, '192.168.2.2/32')).toBeFalsy()
    expect(await isMatch({ addr: '::0', type: 'IPv6' }, '::0/1')).toBeTruthy()
  })

  it('Static Rules', async () => {
    expect(await isMatch({ addr: '192.168.2.1', type: 'IPv4' }, '192.168.2.1')).toBeTruthy()
    expect(await isMatch({ addr: '1234::5678', type: 'IPv6' }, '1234::5678')).toBeTruthy()
    expect(await isMatch({ addr: '::ffff:127.0.0.1', type: 'IPv6' }, '::ffff:127.0.0.1')).toBeTruthy()
    expect(await isMatch({ addr: '::ffff:127.0.0.1', type: 'IPv6' }, '::ffff:7f00:1')).toBeTruthy()
  })

  it('Regex Rules', async () => {
    expect(await isMatch({ addr: '8.8.8.1', type: 'IPv4' }, /^8\.8\.8\.[0-3]$/)).toBeTruthy()
    expect(await isMatch({ addr: '8.8.8.9', type: 'IPv4' }, /^8\.8\.8\.[0-3]$/)).toBeFalsy()
  })

  it('Function Rules', async () => {
    expect(await isMatch({ addr: '0.0.0.0', type: 'IPv4' }, () => true)).toBeTruthy()
    expect(await isMatch({ addr: '0.0.0.0', type: 'IPv4' }, () => false)).toBeFalsy()

    const ipaddr = '93.184.216.34'
    await isMatch({ addr: ipaddr, type: 'IPv4' }, (ip) => {
      expect(ipaddr).toBe(ip.addr)
      return false
    })
  })
})
