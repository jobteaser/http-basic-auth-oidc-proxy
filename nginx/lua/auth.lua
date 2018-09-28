local opts = {
    redirect_uri_path = os.getenv("OID_REDIRECT_PATH") or "/redirect_uri",
    discovery = os.getenv("OID_DISCOVERY"),
    client_id = os.getenv("OID_CLIENT_ID"),
    client_secret = os.getenv("OID_CLIENT_SECRET"),
    token_endpoint_auth_method = os.getenv("OIDC_AUTH_METHOD") or "client_secret_basic",
    renew_access_token_on_expiry = os.getenv("OIDC_RENEW_ACCESS_TOKEN_ON_EXPIERY") ~= "false",
    scope = os.getenv("OIDC_AUTH_SCOPE") or "openid",
    iat_slack = 600,
}

local basic_auth_username = os.getenv("BASIC_AUTH_USERNAME")
local basic_auth_password = os.getenv("BASIC_AUTH_PASSWORD")
local log_user_claim = os.getenv("LOG_USER_CLAIM")

-- authenticate_basic_auth
-- Try to authenticate by Basic Auth
-- return "BASIC_AUTH_SUCCESS" on Basic Auth success
--        "BASIC_AUTH_FAIL" on Basic Auth failure
--        "NO_BASIC_AUTH" if no Basic Auth was attempted
function authenticate_basic_auth()
    -- Test Authentication header is set and with a value
    local header = ngx.req.get_headers()['Authorization']
    if header == nil or header:find(" ") == nil then
        return "NO_BASIC_AUTH"
    end

    local divider = header:find(' ')
    if header:sub(0, divider-1) ~= 'Basic' then
       return "BASIC_AUTH_FAIL"
    end

    local auth = ngx.decode_base64(header:sub(divider+1))
    if auth == nil or auth:find(':') == nil then
       return "BASIC_AUTH_FAIL"
    end

    divider = auth:find(':')
    local username = auth:sub(0, divider-1)
    local password = auth:sub(divider+1)

    if username == basic_auth_username and password == basic_auth_password then
        ngx.log(ngx.INFO, "Authentication successful (Basic Auth) for user " .. username)
        ngx.req.set_header("X-User", username)
        return "BASIC_AUTH_SUCCESS"
    end

    return "BASIC_AUTH_FAIL"
end

function authenticate_oidc()
    -- call authenticate for OpenID Connect user authentication
    local res, err, _target, session = require("resty.openidc").authenticate(opts)

    ngx.log(ngx.INFO, tostring(res))
    ngx.log(ngx.INFO, tostring(err))

    ngx.log(ngx.INFO,
      "session.present=", session.present,
      ", session.data.id_token=", session.data.id_token ~= nil,
      ", session.data.authenticated=", session.data.authenticated,
      ", opts.force_reauthorize=", opts.force_reauthorize,
      ", opts.renew_access_token_on_expiry=", opts.renew_access_token_on_expiry,
      ", try_to_renew=", try_to_renew,
      ", token_expired=", token_expired
    )

    if err then
        ngx.status = 500
        ngx.header.content_type = 'text/html';

        ngx.say("There was an error while logging in: " .. err)
        ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
    end

    ngx.log(ngx.INFO, "Authentication successful, setting Auth header...")
    ngx.req.set_header("Authorization", "Bearer " .. session.data.enc_id_token)
    if log_user_claim then
        ngx.req.set_header("X-User", res.id_token[log_user_claim])
    end
end

local basic_auth = authenticate_basic_auth()

if basic_auth == "BASIC_AUTH_FAIL" then
    -- unsuccessful basic auth authentication tentative, retry / 401
    ngx.header.content_type = 'text/plain'
    ngx.header.www_authenticate = 'Basic realm=""'
    ngx.status = ngx.HTTP_UNAUTHORIZED
    ngx.say('401 Access Denied')
    ngx.exit(ngx.HTTP_UNAUTHORIZED)
elseif basic_auth == "NO_BASIC_AUTH" then
   -- no Basic auth, fallback on OIDC
   authenticate_oidc()
end
