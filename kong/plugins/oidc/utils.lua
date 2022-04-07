local cjson = require("cjson")
local M = {}



local function parseFilters(csvFilters)
    local filters = {}
    if (not (csvFilters == nil)) then
        for pattern in string.gmatch(csvFilters, "[^,]+") do
            table.insert(filters, pattern)
        end
    end
    return filters
end

function M.get_redirect_uri_path(ngx)
    local function drop_query()
        local uri = ngx.var.request_uri
        local x = uri:find("?")
        if x then
            return uri:sub(1, x - 1)
        else
            return uri
        end
    end

    local function tackle_slash(path)
        local args = ngx.req.get_uri_args()
        if args and args.code then
            return path
        elseif path == "/" then
            return "/cb"
        elseif path:sub(-1) == "/" then
            return path:sub(1, -2)
        else
            return path .. "/"
        end
    end

    return tackle_slash(drop_query())
end

function M.get_options(config, ngx)
    return {
        client_id = config.client_id,
        client_secret = config.client_secret,
        jwt_secret = config.jwt_secret,
        discovery = config.discovery,
        introspection_endpoint = config.introspection_endpoint,
        timeout = config.timeout,
        introspection_endpoint_auth_method = config.introspection_endpoint_auth_method,
        introspection_expiry_claim = config.introspection_expiry_claim,
        introspection_interval = config.introspection_interval,
        introspection_cache_ignore = config.introspection_cache_ignore,
        bearer_only = config.bearer_only,
        realm = config.realm,
        redirect_uri_path = config.redirect_uri_path or M.get_redirect_uri_path(ngx),
        redirect_uri = config.redirect_uri,
        scope = config.scope,
        response_type = config.response_type,
        ssl_verify = config.ssl_verify,
        token_endpoint_auth_method = config.token_endpoint_auth_method,
        recovery_page_path = config.recovery_page_path,
        filters = parseFilters(config.filters),
        logout_path = config.logout_path,
        redirect_after_logout_uri = config.redirect_after_logout_uri,
    }
end

function M.get_session_options(config, ngx)
    return {
        name = config.session_name,
        storage = config.session_storage,
        redis = {
            host = config.session_redis_host,
            port = config.session_redis_port,
            prefix = config.session_redis_prefix,
            socket = config.session_redis_socket,
            auth = config.session_redis_auth,
            server_name = config.session_redis_server_name,
        }
    }
end

function M.exit(httpStatusCode, message, ngxCode)
    ngx.status = httpStatusCode
    ngx.say(message)
    ngx.exit(ngxCode)
end

function M.injectBearerCached(jwt)
    print("JWT CAHCED " .. jwt)
    ngx.req.set_header("Authorization","Bearer " .. jwt)
end
function M.injectAccessToken(accessToken, user, secret, client, cookie)    
    --my code
    local jwt = require "resty.jwt"
    local inAnHour = os.time(os.date('*t')) + 3600;
    local roles = "";
    
    for i, role in ipairs(user.roles) do
        roles = roles .. role .. ","
      end
    roles = roles:sub(1, -2)
      
    local jwt_table = { 
        ["header"] = {["typ"] = "JWT", ["alg"] = "HS512"},
        ["payload"] = {
            ["id"] = user.id, 
            ["name"] = user.name,
            ["gn"] = user.given_name,
            ["fn"] = user.family_name,
            ["email"] = user.email,
            ["ev"] = user.email_verified,
            ["ss"] = user.session_state,  
            ["auth_time"] = user.auth_time,
            ["lang"] = user.langKey,
            ["auth"] = roles,
            ["sub"] = user.preferred_username,
            ["exp"] = inAnHour
                    } 
    } 
    local jwt_obj = jwt:sign(secret, jwt_table)
    
    if(client:ping()) then
        client:set("jwt:" .. cookie , jwt_obj)
    end
    ngx.req.set_header("Authorization","Bearer " .. jwt_obj)
    --ngx.req.set_header("X-accessToken", accessToken)
    -- end my code
        
end

function M.injectIDToken(idToken)
    local tokenStr = cjson.encode(idToken)
    --ngx.req.set_header("X-ID-Token", ngx.encode_base64(tokenStr))
end

function M.injectUser(user, secret)
    local tmp_user = user
    tmp_user.id = user.sub
    tmp_user.username = user.preferred_username
    ngx.ctx.authenticated_credential = tmp_user
    local userinfo = cjson.encode(user)  
    --ngx.req.set_header("X-Userinfo", ngx.encode_base64(userinfo))
end


function M.has_bearer_access_token()
    local header = ngx.req.get_headers()['Authorization']
    if header and header:find(" ") then
        local divider = header:find(' ')
        if string.lower(header:sub(0, divider - 1)) == string.lower("Bearer") then
            return true
        end
    end
    return false
end

return M
