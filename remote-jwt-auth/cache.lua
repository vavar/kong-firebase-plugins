local timestamp = require "kong.tools.timestamp"
local reports = require "kong.reports"
local redis = require "resty.redis"

local kong = kong
local pairs = pairs
local null = ngx.null
local fmt = string.format

local sock_opts = {}
local shared = ngx.shared
local max = math.max

local function is_present(str)
    return str and str ~= "" and str ~= null
end

local function dump(o)
    if type(o) == 'table' then
        local s = '{ '
        for k, v in pairs(o) do
            if type(k) ~= 'number' then
                k = '"' .. k .. '"'
            end
            s = s .. '[' .. k .. '] = ' .. dump(v) .. ','
        end
        return s .. '} '
    else
        return tostring(o)
    end
end

local function get_redis_connection(conf)
    local red = redis:new()
    red:set_timeout(conf.redis_timeout)

    sock_opts.ssl = conf.redis_ssl
    sock_opts.ssl_verify = conf.redis_ssl_verify
    sock_opts.server_name = conf.redis_server_name

    kong.log.err("redis_database=", conf.redis_database)

    -- use a special pool name only if redis_database is set to non-zero
    -- otherwise use the default pool name host:port
    if conf.redis_database ~= 0 then
        sock_opts.pool = fmt("%s:%d;%d", conf.redis_host, conf.redis_port, conf.redis_database)
    end

    local ok, err = red:connect(conf.redis_host, conf.redis_port, sock_opts)
    if not ok then
        kong.log.err("failed to connect to Redis: ", err)
        return nil, err
    end

    local times, err = red:get_reused_times()
    if err then
        kong.log.err("failed to get connect reused times: ", err)
        return nil, err
    end

    if times == 0 then
        if is_present(conf.redis_password) then
            local ok, err
            if is_present(conf.redis_username) then
                ok, err = red:auth(conf.redis_username, conf.redis_password)
            else
                ok, err = red:auth(conf.redis_password)
            end

            if not ok then
                kong.log.err("failed to auth Redis: ", err)
                return nil, err
            end
        end

        if conf.redis_database ~= 0 then
            -- Only call select first time, since we know the connection is shared
            -- between instances that use the same redis database

            local ok, err = red:select(conf.redis_database)
            if not ok then
                kong.log.err("failed to change Redis database: ", err)
                return nil, err
            end
        end
    end

    return red
end

-- local _M = {}

-- function _M:store(key, obj, expire_at)
--     local ttl = max(1, expire_at - os.time())
--     local success, err = shared.remote_jwt_auth:set(key, obj, ttl)
--     if success then
--         return true
--     else
--         return nil, err
--     end
-- end

-- function _M:get(key)
--     local obj, err = shared.remote_jwt_auth:get(key)
--     if not obj then
--         if not err then
--             return nil, nil
--         else
--             kong.log("Error when reading cache ", err)
--             return nil, err
--         end
--     end
--     return obj
-- end

return {
    ["local"] = {
        store = function(conf, key, obj, expire_at)
            local ttl = max(1, expire_at - os.time())
            local success, err = shared.remote_jwt_auth:set(key, obj, ttl)
            if success then
                return true
            else
                return nil, err
            end

        end,
        get = function(conf, key)
            local obj, err = shared.remote_jwt_auth:get(key)
            if not obj then
                if not err then
                    return nil, nil
                else
                    kong.log("Error when reading cache ", err)
                    return nil, err
                end
            end
            return obj
        end
    },
    ["redis"] = {
        store = function(conf, key, obj, expire_at)
            local rds, err = get_redis_connection(conf)
            if not rds then
                return nil, err
            end

            local ttl = max(1, expire_at - os.time())

            rds:init_pipeline()
            rds:set(key, obj)
            rds:expire(key, ttl)

            local _, err = rds:commit_pipeline()
            if err then
                kong.log.err("failed to commit increment pipeline in Redis: ", err)
                return nil, err
            end

            -- put it into the connection pool of size 100,
            -- with 10 seconds max idle time
            local ok, err = rds:set_keepalive(10000, 100)
            if not ok then
                kong.log.err("failed to set Redis keepalive: ", err)
                return nil, err
            end

            return true
        end,
        get = function(conf, key)
            local rds, err = get_redis_connection(conf)
            if not rds then
                return nil, err
            end

            local obj, err = rds:get(key)
            if err then
                return nil, err
            end

            local ok, err = rds:set_keepalive(10000, 100)
            if not ok then
                kong.log.err("failed to set Redis keepalive: ", err)
            end

            return obj
        end,
        hmset = function(conf, key, value, expire_at)
            local rds, err = get_redis_connection(conf)
            if not rds then
                return nil, err
            end

            local ttl = max(1, expire_at)

            rds:init_pipeline()
            rds:hmset(key, "user_id", value.user_id, "user_email", value.user_email)
            rds:expire(key, ttl)

            local _, err = rds:commit_pipeline()
            if err then
                kong.log.err("failed to commit increment pipeline in Redis: ", err)
                return nil, err
            end

            -- put it into the connection pool of size 100,
            -- with 10 seconds max idle time
            local ok, err = rds:set_keepalive(10000, 100)
            if not ok then
                kong.log.err("failed to set Redis keepalive: ", err)
                return nil, err
            end

            return true
        end,
        hmget = function(conf, key)
            local rds, err = get_redis_connection(conf)
            if not rds then
                return nil, err
            end

            local obj, err = rds:hmget(key)
            if err then
                return nil, err
            end

            local ok, err = rds:set_keepalive(10000, 100)
            if not ok then
                kong.log.err("failed to set Redis keepalive: ", err)
            end

            return obj
        end
    }
}
