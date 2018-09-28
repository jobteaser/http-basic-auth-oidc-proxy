# jobteaser/http-basic-auth-oidc-proxy [![Image Layers](https://images.microbadger.com/badges/image/jobteaser/http-basic-auth-oidc-proxy.svg)](https://microbadger.com/#/images/jobteaser/http-basic-auth-oidc-proxy)

Docker Image for Basic Auth and OpenID Connect proxy authentication.
Useful for putting services behind Keycloak and other OpenID Connect
authentication with Basic Auth compatibility for service accounts.

This is Image used Nginx for proxying request and OpenResty with the
`lua-resty-openidc` library to handle OpenID Connect authentication.

It is heavily based on [docker-oidc-proxy](https://github.com/evry/docker-oidc-proxy)
as well as this [gist](https://gist.github.com/mariocesar/cdb9fdc6f95a1993e218).

## Supported tags and respective Dockerfile links

* [`latest`, `v1.0.0` (*Dockerfile*)](https://github.com/jobteaser/http-basic-auth-oidc-proxy/blob/master/Dockerfile)

## How to use this image

This proxy is controlled through environment variables, so there is no need to
mess with any configuration files unless you want to of course. The following
environment variables is used in this image:

* `OID_SESSION_SECRET`: secret value for cookie sessions
* `OID_SESSION_CHECK_SSI`: check SSI or not (`on` or `off`)
* `OID_SESSION_NAME`: cookie session name

* `OID_REDIRECT_PATH`: Redirect path after authentication
* `OID_DISCOVERY`: OpenID provider well-known discovery URL
* `OID_CLIENT_ID`: OpenID Client ID
* `OID_CLIENT_SECRET`: OpenID Client Secret
* `OIDC_AUTH_METHOD`: OpenID Connect authentication method (`client_secret_basic` or `client_secret_post`)
* `OIDC_AUTH_SCOPE`: OpenID scopes separated by space (defaults to `"openid"`)
* `OIDC_RENEW_ACCESS_TOKEN_ON_EXPIERY`: Enable silent renew of access token (`true` or `false`)

* `LOG_USER_CLAIM`: if a claim is specified (eg `email`), report it to upstream with `X-User` header

* `BASIC_AUTH_USERNAME`: username authorized for basic auth
* `BASIC_AUTH_PASSWORD`: password authorized for basic auth

* `PROXY_HOST`: Host name of the service to proxy
* `PROXY_PORT`: Port of the service to proxy
* `PROXY_PROTOCOL`: Protofol to the service to proxy (`http` or `https`)

```
docker run \
  -e OID_DISCOVERY=https://my-auth-server/auth \
  -e OID_CLIENT_ID=my-client \
  -e OID_CLIENT_SECRET=my-secret \
  -e BASIC_AUTH_USERNAME=poweradmin \
  -e BASIC_AUTH_PASSWORD=my-secured-password \
  -e PROXY_HOST=my-service \
  -e PROXY_PORT=80 \
  -e PROXY_PROTOCOL=http \
  -p 80:80 \
  jobteaser/http-basic-auth-oidc-proxy
```

## License

This Docker image is licensed under the [Apache License 2.0](https://github.com/jobteaser/http-basic-auth-oidc-proxy/blob/master/LICENSE).

Software contained in this image is licensed under the following:

* docker-oidc-proxy: [MIT License](https://github.com/evry/docker-oidc-proxy/blob/master/LICENSE)
* docker-openresty: [BSD 2-clause "Simplified" License](https://github.com/openresty/docker-openresty/blob/master/COPYRIGHT)
* lua-resty-http: [BSD 2-clause "Simplified" License](https://github.com/pintsized/lua-resty-http/blob/master/LICENSE)
* lua-resty-jwt: [Apache License 2.0](https://github.com/cdbattags/lua-resty-jwt/blob/master/LICENSE.txt)
* lua-resty-openidc: [Apache License 2.0](https://github.com/zmartzone/lua-resty-openidc/blob/master/LICENSE.txt)
* lua-resty-session: [BSD 2-clause "Simplified" License](https://github.com/bungle/lua-resty-session/blob/master/LICENSE)
* lua-resty-hmac: [BSD 2-clause "Simplified" License](https://github.com/jkeys089/lua-resty-hmac/#copyright-and-license)

## Supported Docker versions

This image is officially supported on Docker version 1.12.

Support for older versions (down to 1.0) is provided on a best-effort basis.

## User Feedback

### Documentation

* [Docker](http://docs.docker.com)
* [nginx](http://nginx.org/en/docs/)
* [OpenResty](http://openresty.org/)
* [lua-resty-openidc](https://github.com/zmartzone/lua-resty-openidc#readme)

### Issues

If you have any problems with or questions about this image, please contact us
through a [GitHub issue](https://github.com/jobteaser/http-basic-auth-oidc-proxy/issues).
