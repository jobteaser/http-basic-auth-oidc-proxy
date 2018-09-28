local basic_auth = {}
basic_auth.__index = basic_auth

function auth_fail()
    -- unsuccessful basic auth authentication tentative, retry / 401
    ngx.header.content_type = 'text/plain'
    ngx.header.www_authenticate = 'Basic realm=""'
    ngx.status = ngx.HTTP_UNAUTHORIZED
    ngx.say('401 Access Denied')
    ngx.exit(ngx.HTTP_UNAUTHORIZED)
end

-- perform a Basic Auth check
-- return true on auth success
-- return false if no auth was attempted
-- exit with 401 on auth failure
function basic_auth.authenticate(opts)
    -- Test Authentication header is set and with a value
    local header = ngx.req.get_headers()['Authorization']
    if header == nil or header:find(" ") == nil then
        return false
    end

    local divider = header:find(' ')
    if header:sub(0, divider-1) ~= 'Basic' then
       basic_auth_fail()
    end

    local auth = ngx.decode_base64(header:sub(divider+1))
    if auth == nil or auth:find(':') == nil then
       auth_fail()
    end

    divider = auth:find(':')
    local username = auth:sub(0, divider-1)
    local password = auth:sub(divider+1)

    if username == opts.basic_auth_username and password == opts.basic_auth_password then
        ngx.log(ngx.INFO, "Authentication successful (Basic Auth) for user " .. username)
        ngx.req.set_header("X-User", username)
        return true
    end

    basic_auth_fail()
end

return basic_auth
