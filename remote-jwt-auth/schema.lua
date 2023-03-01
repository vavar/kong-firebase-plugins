local typedefs = require "kong.db.schema.typedefs"

return {
    name = "remote-jwt-auth",
    fields = {{
        consumer = typedefs.no_consumer
    }, {
        protocols = typedefs.protocols_http
    }, {
        config = {
            type = "record",
            fields = {{
                anonymous = {
                    type = "boolean",
                    default = true
                }
            }, {
                authenticated_consumer = {
                    type = "string",
                    required = true
                }
            }, {
                signing_urls = {
                    type = "array",
                    elements = {
                        type = "string"
                    },
                    default = {
                        -- Pub/Sub:
                        -- "https://www.googleapis.com/oauth2/v1/certs",
                        --
                        -- Firebase:
                        -- "https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com",
                    }
                }
            }, {
                cache_namespace = {
                    type = "string",
                    required = true,
                    default = "remote-jwt-auth"
                }
            }, {
                cache_type = {
                    type = "string",
                    default = "local",
                    len_min = 0,
                    one_of = {"local", "redis"}
                }
            }, {
                claims_to_verify = {
                    type = "array",
                    elements = {
                        type = "record",
                        fields = {{
                            name = {
                                type = "string",
                                required = true
                            }
                        }, {
                            allowed_values = {
                                type = "array",
                                required = true,
                                elements = {
                                    type = "string"
                                }
                            }
                        }}
                    },
                    default = {}
                }
            }, {
                redis_database = {
                    type = "integer",
                    default = 0
                }
            }, {
                redis_host = typedefs.host
            }, {
                redis_port = typedefs.port({
                    default = 6379
                })
            }, {
                redis_password = {
                    type = "string",
                    len_min = 0,
                    referenceable = true
                }
            }, {
                redis_username = {
                    type = "string",
                    referenceable = true
                }
            }, {
                redis_ssl = {
                    type = "boolean",
                    required = true,
                    default = false
                }
            }, {
                redis_ssl_verify = {
                    type = "boolean",
                    required = true,
                    default = false
                }
            }, {
                redis_server_name = typedefs.sni
            }, {
                redis_timeout = {
                    type = "number",
                    default = 2000
                }
            }, {
                timeout = {
                    type = "number",
                    default = 10000
                }
            }}
        }
    }}
}
