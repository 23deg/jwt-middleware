# JWT Middleware

JWT Middleware is a middleware plugin for [Traefik](https://github.com/containous/traefik) which verifies a jwt token and adds the payload as injected header to the request

## Configuration

Activate plugin in your config  

```yaml
http:
  middlewares:
    my-jwt-middleware:
      plugin:
        jwt-middleware:
          secret: SECRET
          proxyHeaderName: injectedPayload
          authHeader: Authorization
          headerPrefix: Bearer
```

Use as docker-compose label  
```yaml
  labels:
        - "traefik.http.routers.my-service.middlewares=my-jwt-middleware@file"
```
