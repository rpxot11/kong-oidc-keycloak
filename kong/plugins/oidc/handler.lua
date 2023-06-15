local BasePlugin = require "kong.plugins.base_plugin"
local OidcHandler = BasePlugin:extend()
local utils = require("kong.plugins.oidc.utils")
local filter = require("kong.plugins.oidc.filter")
local session = require("kong.plugins.oidc.session")
local redis = require "resty.redis"
local socket = require("socket")
local uuid = require("uuid")

OidcHandler.PRIORITY = 1000

function OidcHandler:new()
    OidcHandler.super.new(self, "oidc")
end

function OidcHandler:access(config)
    OidcHandler.super.access(self)
    local oidcConfig = utils.get_options(config, ngx)
    local sessionConfig = utils.get_session_options(config, ngx)

    if filter.shouldProcessRequest(oidcConfig) then
        session.configure(config)
        handle(oidcConfig, sessionConfig)
    else
        ngx.log(ngx.DEBUG, "OidcHandler ignoring request, path: " .. ngx.var.request_uri)
    end
end


function handle(oidcConfig, sessionConfig)
    ngx.log(ngx.DEBUG, "*************** URI :  ***************" )
    local uri = ngx.var.request_uri;
    ngx.log(ngx.DEBUG, uri)
    

    if string.find(uri, "/oauth2/authorization/oidc") then
        print ("The word authorization was found.")
        login(oidcConfig, sessionConfig);
        else if string.find(uri, "logout") then 
            logout(oidcConfig, sessionConfig)
            
        else  
            local cookieName = sessionConfig.jwt.cookie_name
            local var_name = "cookie_" .. cookieName
            local cookie_value = ngx.var[var_name]
        
            if(cookie_value ~= nil)
            then
                ngx.log(ngx.DEBUG, "***************  Cookie  :  ***************" )
                ngx.log(ngx.DEBUG, cookie_value)
    
                local token = getTokenfromCache(oidcConfig, sessionConfig, cookie_value, sessionConfig.redis.host, sessionConfig.redis.port, sessionConfig.jwt.secret)
                if(token ~= nil)
                then 
                    ngx.log(ngx.DEBUG, "***************  Cache value :  ***************" )
                    ngx.log(ngx.DEBUG, token)
                    utils.injectAccessToken(token)
                else 
                    -- local tokenUpdated = update_login(oidcConfig, sessionConfig, cookie_value);
                    -- if(tokenUpdated ~= nil) then 
                    --     ngx.log(ngx.DEBUG, "***************  New Cache value :  ***************" )
                    --     ngx.log(ngx.DEBUG, tokenUpdated)
                    --     utils.injectAccessToken(tokenUpdated)
                    -- end
                    utils.exit(401, err, ngx.HTTP_UNAUTHORIZED)
                end
            else 
                --remove authoriation header  
            end
    end
end

    -- local response
    -- -- bearer only code (needs to send authorization header)
    -- if oidcConfig.introspection_endpoint then
    --     response = introspect(oidcConfig)
    --     if response then
    --         ngx.log(ngx.DEBUG, "User found from introspection")
    --         utils.injectUser(response)
    --     end
    -- end

    -- if response == nil then
    --     response = make_oidc(oidcConfig, sessionConfig)
    --     if response then
    --         if (response.user) then
    --             ngx.log(ngx.DEBUG, "OidcHandler INJECT USER: ")
    --             utils.injectUser(response.user)
    --         end
    --         if (response.access_token) then
    --             ngx.log(ngx.DEBUG, "OidcHandler ACCESS TOKEN: ")
    --             utils.injectAccessToken(response.access_token)
    --         end
    --         if (response.id_token) then
    --             ngx.log(ngx.DEBUG, "OidcHandler ID TOKEN: ")
    --             utils.injectIDToken(response.id_token)
    --         end
    --     end
    -- end
end


function getTokenfromCache(oidcConfig, sessionConfig, cookie_value, host, port, secret)
    ngx.log(ngx.DEBUG, "********* GETTING TOKEN FROM CACHE ***********");
    local token = cache_get("session_jwt:".. cookie_value, host, port)
    if(token ~= nil)
    then
        ngx.log(ngx.DEBUG, "********* token not nil ***********");
        local timestamp = cache_get("session_jwt:".. cookie_value .. ":timestamp", host, port)
        if(timestamp ~= nil)
        then
            ngx.log(ngx.DEBUG, "timestamp " .. timestamp);
            local inFiveMinuts = os.time(os.date('*t')) + 60;
            local inThirtyMinuts = os.time(os.date('*t')) + 14400;
            if(tonumber(timestamp) <  inFiveMinuts)
            then
                ngx.log(ngx.DEBUG, "timestamp < 5 minuts ");
                ngx.log(ngx.DEBUG, " ******************** TIMESTAMP UPDATE ***********************");
                --refresh timestamp
                cache_set("session_jwt:".. cookie_value .. ":timestamp", inThirtyMinuts, 43200,  host, port) 
                response = make_oidc(oidcConfig, sessionConfig);
                if response then
                    ngx.log(ngx.DEBUG, "Update sucess");
                    token = utils.getJwtAccessToken(response.access_token, response.user, secret)
                    cache_set("session_jwt:" .. cookie_value , token, 43200, host, port)                    
                end          
            end
            return token;
        end
    end
    utils.exit(401, err, ngx.HTTP_UNAUTHORIZED)
end

function login(oidcConfig, sessionConfig)
    local inThirtyMinuts = os.time(os.date('*t')) + 14400;
    response = make_oidc(oidcConfig, sessionConfig);
    if response then
        uuid.seed()
        local uuid = uuid()
        --local uuid = "12342135124542151425wfmlkwmfl12435124451245"
        ngx.log(ngx.DEBUG, "Login sucess");
        local token = utils.getJwtAccessToken(response.access_token, response.user, sessionConfig.jwt.secret)
        --cache_set("session_jwt:" .. uuid , token, sessionConfig.jwt.timeout, sessionConfig.redis.host, sessionConfig.redis.port)
        cache_set("session_jwt:" .. uuid , token, 43200, sessionConfig.redis.host, sessionConfig.redis.port)
        cache_set("session_jwt:".. uuid .. ":timestamp" , inThirtyMinuts, 43200, sessionConfig.redis.host, sessionConfig.redis.port)
        ngx.header['Set-Cookie'] =  sessionConfig.jwt.cookie_name.."=" .. uuid .. "; path=/"
        return ngx.redirect("/")
    end
end

function logout(oidcConfig, sessionConfig)
    -- response = make_oidc_logout(oidcConfig, sessionConfig);
    -- if response then
    --     ngx.log(ngx.DEBUG, "Logout sucess");
    --     --ngx.header['Set-Cookie'] =  sessionConfig.jwt.cookie_name.."=" .. uuid .. "; path=/"
    --     return ngx.redirect("/")
    -- end
    ngx.log(ngx.DEBUG, " ******************** Logout Process **********************");
    ngx.header['Set-Cookie'] =  "TMLCRM=; Max-Age=0; Expires=Thu, 1 Jan 1970 00:00:00 GMT; Path=/; Secure; HttpOnly; SameSite=Lax";
    return nxg.Response(200, "www.google.pt");
end

function update_login(oidcConfig, sessionConfig, cookie_value)
    response = make_oidc(oidcConfig, sessionConfig);
    if response then
        ngx.log(ngx.DEBUG, "Update sucess");
        local token = utils.getJwtAccessToken(response.access_token, response.user, sessionConfig.jwt.secret)
        cache_set("session_jwt:" .. cookie_value , token, sessionConfig.jwt.timeout, sessionConfig.redis.host, sessionConfig.redis.port)
        return token;
    end
end

function make_oidc(oidcConfig, sessionConfig)
    ngx.log(ngx.DEBUG, "OidcHandler calling authenticate, requested path: " .. ngx.var.request_uri)
    local res, err = require("resty.openidc").authenticate(oidcConfig, nil, nil, sessionConfig)
    if err then
        if oidcConfig.recovery_page_path then
            ngx.log(ngx.DEBUG, "Entering recovery page: " .. oidcConfig.recovery_page_path)
            ngx.redirect(oidcConfig.recovery_page_path)
        end
        ngx.log(ngx.DEBUG, "ERROR OIDC HANDLER MAKE OIDC: " .. err)
        utils.exit(500, err, ngx.HTTP_INTERNAL_SERVER_ERROR)
    end
    return res
end

function make_oidc_logout(oidcConfig, sessionConfig)
    ngx.log(ngx.INFO, "OidcHandler calling logout, requested path: " .. ngx.var.request_uri)
    local res, err = require("resty.openidc").authenticate(oidcConfig, nil, nil, sessionConfig)
    if err then
        if oidcConfig.recovery_page_path then
            ngx.log(ngx.DEBUG, "Entering recovery page: " .. oidcConfig.recovery_page_path)
            ngx.redirect(oidcConfig.recovery_page_path)
        end
        utils.exit(500, err, ngx.HTTP_INTERNAL_SERVER_ERROR)
    end
    return res
end


function introspect(oidcConfig)
    ngx.log(ngx.INFO, utils.has_bearer_access_token())
    if utils.has_bearer_access_token() or oidcConfig.bearer_only == "yes" then
        local res, err = require("resty.openidc").introspect(oidcConfig)
        if err then
            if oidcConfig.bearer_only == "yes" then
                ngx.header["WWW-Authenticate"] = 'Bearer realm="' .. oidcConfig.realm .. '",error="' .. err .. '"'
                utils.exit(ngx.HTTP_UNAUTHORIZED, err, ngx.HTTP_UNAUTHORIZED)
            end
            return nil
        end
        ngx.log(ngx.DEBUG, "OidcHandler introspect succeeded, requested path: " .. ngx.var.request_uri)
        return res
    end
    return nil
end


-- set value in server-wide cache if available
function cache_set(key, value, exp, redisHost, redisPort)
    ngx.log(ngx.DEBUG, "******* CACHE SET START ******")
    --ngx.log(ngx.DEBUG, "key: " .. key)
    --ngx.log(ngx.DEBUG, "value: " .. value)
    --ngx.log(ngx.DEBUG, "exp: " .. exp)
    local red = redis:new()
    red:set_timeout(1000)  -- 1 second~
    local ok, err = red:connect(redisHost, redisPort)
    if not ok then
        ngx.say("Failed to connect to Redis: ", err)
        return
    end
    
    local ok, err = red:set(key, value)
    if not ok then
        ngx.say("Failed to set key-value pair in Redis: ", err)
        return
    end

    -- Set an expiration time of 60 seconds for the key
    local ok, err = red:expire(key, exp)
    if not ok then
        ngx.say("Failed to set expiration time for key: ", err)
        return
    end
    ngx.log(ngx.DEBUG, "******* CACHE SET END ******")
    red:close()
end
  
  -- retrieve value from server-wide cache if available
function cache_get(key , redisHost, redisPort)
    ngx.log(ngx.DEBUG, "CAHCE GET SATART")
    local red = redis:new()
    red:set_timeout(1000)  -- 1 second

    local ok, err = red:connect(redisHost, redisPort)
    if not ok then
        ngx.say("Failed to connect to Redis: ", err)
        return
    end
     
    -- Get the ttl of the key
    local ttl, err = red:ttl(key)
    if not ttl then
        ngx.say("Failed to get ttl from Redis: ", err)
        return
    else 
        ngx.log(ngx.DEBUG, "SOME TTL FOUND " .. ttl)
    end
    
    -- Check if the ttl is greater than 0
    if ttl > 0 then
        -- Get the value from Redis
        local res, err = red:get(key)
        if not res then
            ngx.say("Failed to get value from Redis: ", err)
            return
        end
        --ngx.log(ngx.DEBUG, res)
        return res;
    end
end 


return OidcHandler
