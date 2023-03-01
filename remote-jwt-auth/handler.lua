local http = require "resty.http"
local cjson = require "cjson"
local ssl = require "ngx.ssl"
local x509 = require "resty.openssl.x509"
local sha512 = require "resty.sha512"
local to_hex = require("resty.string").to_hex
local constants = require("kong.constants")
local jwt_decoder = require "kong.plugins.jwt.jwt_parser"
local cache = require "kong.plugins.remote-jwt-auth.cache"
local assert = assert

local RemoteJWTAuthHandler = {
    VERSION = "1.0.0",
    PRIORITY = 1500
}

local AUTHORIZATION = "authorization"
local PROXY_AUTHORIZATION = "proxy-authorization"

local TOKEN_USER_ID = "X-Token-User-Id"
local TOKEN_USER_EMAIL = "X-Token-User-Email"
local TOKEN_USER_ROLE = "X-Token-Role"

local CACHE_PREFIX_CERTS = "certs"
local CACHE_PREFIX_USERS = "users"

local function generate_cache_key(config, prefix, key)
    local digest = sha512:new()
    assert(digest:update(config.cache_namespace))
    assert(digest:update(key))
    return config.cache_namespace .. ":" .. prefix .. ":" .. to_hex(digest:final())
end

local function fetch_signing_certificates(config, url)
    local httpc, err = http.new()
    if httpc == nil then
        kong.log.err("Failed to start a http request: ", err)
        return nil, err
    end
    httpc:set_timeout(config.timeout)
    local start_of_request = os.time()
    local res, err = httpc:request_uri(url, {})
    if res == nil then
        kong.log.err("Request for certificate failed: ", err)
        return nil, err
    end

    local cache_control_header = res.headers["Cache-Control"]
    if cache_control_header == nil then
        kong.log.err("Could not find cache control header")
        return nil, "Could not find cache control header"
    end
    local _, _, max_age_string = string.find(cache_control_header, "max%-age=(%d+)")
    if max_age_string == nil then
        kong.log.err("Could not find max-age string in cache control")
        return nil, "Could not find max-age string in cache control"
    end
    local max_age = tonumber(max_age_string)
    local expires_at = start_of_request + max_age

    local response_body = cjson.decode(res.body)

    local valid_certs = {}
    for kid, cert in pairs(response_body) do
        local parsed_cert_chain, err = ssl.parse_pem_cert(cert)
        if parsed_cert_chain == nil then
            kong.log.err("Failed to parse cert ", err)
            return nil, err
        end
        valid_certs[kid] = cert
        local success, err = cache[config.cache_type].store(config, generate_cache_key(config, CACHE_PREFIX_CERTS, kid),
            cert, expires_at)
        if not success then
            kong.log.err("Failed writing to the cache: ", err)
            return nil, err
        end
    end
    return valid_certs
end

local function get_signing_certificates(config, target_kid)
    local jwt_cache_key = generate_cache_key(config, CACHE_PREFIX_CERTS, target_kid)
    local cached_cert, err = cache[config.cache_type].get(config, jwt_cache_key)
    if err then
        kong.log.err("Failed to get cached cert ", err)
        return nil, err
    end
    if cached_cert ~= ngx.null then
        kong.log.err("found existing cache cert - ", cached_cert)
        local parsed_cert_chain, err = ssl.parse_pem_cert(cached_cert)
        if parsed_cert_chain == nil then
            kong.log.err("Failed to parse cert ", err)
            return nil, err
        end
        return cached_cert
    end

    -- call fetch signing certificates
    for _, url in ipairs(config.signing_urls) do
        local valid_certs, err = fetch_signing_certificates(config, url)
        if err then
            kong.log.err("Error fetching certs from ", url, ": ", err)
        else
            local parsed_cert = valid_certs[target_kid]
            if parsed_cert then
                return parsed_cert
            end
        end
    end

    kong.log.err("No certs matching kid ", target_kid, " found in the signing_urls.")
    return nil, "No matching kid found."
end

local function list_contains(haystack, needle)
    for _, hay in ipairs(haystack) do
        if hay == needle then
            return true
        end
    end
    return false
end

local function do_authentication(config, jwt_token)

    local jwt, err = jwt_decoder:new(jwt_token)
    if err then
        kong.log("Not a valid JWT: ", err)
        return nil, {
            status = 401,
            message = "Bad token"
        }
    end
    local kid = jwt.header.kid
    if not kid then
        return false, {
            status = 401,
            message = "Unauthorized"
        }
    end

    local signing_cert, err = get_signing_certificates(config, kid)
    if not signing_cert then
        kong.log.err("Failed to get signing certificate.")
        return nil, {
            status = 401,
            message = "Unauthorized"
        }
    end

    local parsed_signing_cert, err = x509.new(signing_cert)
    if not parsed_signing_cert then
        kong.log.err("Failed to parse signing cert.")
        return nil, {
            status = 401,
            message = "Unauthorized"
        }
    end

    if not jwt:verify_signature(parsed_signing_cert:get_pubkey():tostring()) then
        kong.log.err("Invalid signature.")
        return nil, {
            status = 401,
            message = "Invalid signature"
        }
    end

    for _, claim_to_verify in ipairs(config.claims_to_verify) do
        local claim_in_jwt = jwt.claims[claim_to_verify.name]
        if not claim_in_jwt then
            kong.log("JWT lacks a ", claim_to_verify.name, " name.")
            return nil, {
                status = 401,
                message = "Unauthorized"
            }
        end

        if not list_contains(claim_to_verify.allowed_values, claim_in_jwt) then
            kong.log("Disallowed value for claim ", claim_to_verify.name, ": ", claim_in_jwt)
            return nil, {
                status = 401,
                message = "Unauthorized"
            }
        end
    end

    return {
        user_id = jwt.claims.sub,
        user_email = jwt.claims.email,
        user_role = jwt.claims.role
    }
end

local function set_jwt_header(result)
    local set_header = kong.service.request.set_header

    if not result then
        return
    end

    if result.user_id then
        set_header(TOKEN_USER_ID, result.user_id)
    end

    if result.user_email then
        set_header(TOKEN_USER_EMAIL, result.user_email)
    end

    if result.user_role then
        set_header(TOKEN_USER_ROLE, result.user_role)
    end
end

function RemoteJWTAuthHandler:access(config)

    -- If both headers are missing, return 401
    local authorization_value = kong.request.get_header(AUTHORIZATION)
    local proxy_authorization_value = kong.request.get_header(PROXY_AUTHORIZATION)
    local jwt_value = authorization_value and authorization_value or proxy_authorization_value

    if not jwt_value then
        if not config.anonymous then
            return kong.response.exit(401, {
                message = "Unauthorized"
            })
        else
            return -- allow anonymous
        end
    end

    local cacher = cache[config.cache_type]
    local without_bearer = string.gsub(jwt_value, "^[Bb]earer ", "")
    local token_cache_key = generate_cache_key(config, CACHE_PREFIX_USERS, without_bearer)
    local cache_obj, err = cacher.hmget(config, token_cache_key)

    local set_header = kong.service.request.set_header
    if cache_obj ~= ngx.null and not err then
        set_jwt_header(cache_obj)
        return
    end

    local result, err = do_authentication(config, without_bearer)
    if err and not config.anonymous then
        return kong.response.exit(err.status, {
            message = err.message
        })
    end
    if result and not err then
        set_jwt_header(result)
        err = cacher.hmset(config, token_cache_key, result, 900)
        return
    end

end

return RemoteJWTAuthHandler
