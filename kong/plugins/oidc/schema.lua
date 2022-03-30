return {
  no_consumer = true,
  fields = {
    client_id = { type = "string", required = true },
    client_secret = { type = "string", required = true },
    jwt_secret = { type = "string", required = true },
    discovery = { type = "string", required = true, default = "https://.well-known/openid-configuration" },
    introspection_endpoint = { type = "string", required = false },
    timeout = { type = "number", required = false },
    introspection_endpoint_auth_method = { type = "string", required = false },
    introspection_expiry_claim = { type = "string", required = false, default = "exp" },
    introspection_interval = { type = "number", required = false, default = 0 },
    introspection_cache_ignore = { type = "boolean", required = false, default = false },
    bearer_only = { type = "string", required = true, default = "no" },
    realm = { type = "string", required = true, default = "kong" },
    redirect_uri_path = { type = "string" },
    redirect_uri = { type = "string" },
    scope = { type = "string", required = true, default = "openid" },
    response_type = { type = "string", required = true, default = "code" },
    ssl_verify = { type = "string", required = true, default = "no" },
    token_endpoint_auth_method = { type = "string", required = true, default = "client_secret_post" },
    session_secret = { type = "string", required = false },
    recovery_page_path = { type = "string" },
    logout_path = { type = "string", required = false, default = '/logout' },
    redirect_after_logout_uri = { type = "string", required = false, default = '/' },
    filters = { type = "string" },
    session_name = { type = "string", required = false, default = 'session' },
    session_storage = { type = "string", required = false, default = 'cookie' },
    session_redis_host = { type = "string", required = false, default = '127.0.0.1' },
    session_redis_port = { type = "string", required = false, default = '6379' },
    session_redis_server_name = { type = "string", required = false },
    session_redis_auth = { type = "string", required = false },
    session_redis_uselocking = { type = "string", required = false },
    session_redis_database = { type = "string", required = false },
    session_redis_prefix = { type = "string", required = false },
    session_redis_ssl = { type = "string", required = false, default = 'off' },
    session_redis_ssl_verify = { type = "string", required = false, default = 'off'},
  }
}
