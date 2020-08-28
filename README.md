# JWT Middleware

JWT Middleware is a middleware plugin for [Traefik](https://github.com/containous/traefik) which verifies a jwt token and adds the payload as injected header to the request

## TODOS
### High priority
- Correct Errorhandling!
- TESTS!
- README
- expiration check

### Low priority
- add more hash algorithms 

## Configuration

secret: SECRET,
proxyHeaderName: injectedPayload,
authHeader: Authentication,

### Static

TODO

### Dynamic

TODO