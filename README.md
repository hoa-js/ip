## @hoajs/ip

IP restriction middleware for Hoa.

## Installation

```bash
$ npm i @hoajs/ip --save
```

## Quick Start

```js
import { Hoa } from 'hoa'
import { ip } from '@hoajs/ip'

const app = new Hoa()

app.use(ip({
  // By default, client IP is read from 'CF-Connecting-IP' header.
  // getIp: (ctx) => ctx.req.get('CF-Connecting-IP'),
  allowList: ['127.0.0.1', '::1'],
  denyList: ['203.0.113.0/24', /1.2.3.[0-9]{1,3}/],
  denyHandler: (ctx) => ctx.throw(403, 'Forbidden')
}))

app.use(async (ctx) => {
  ctx.res.body = 'Hello, Hoa!'
})

export default app
```

## Documentation

The documentation is available on [hoa-js.com](https://hoa-js.com/middleware/ip.html)

## Test (100% coverage)

```sh
$ npm test
```

## License

MIT
