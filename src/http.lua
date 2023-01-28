local socket = require("socket")

------------------------------------------------------------------------------------------------------------------------
--- Base64
--- @see http://lua-users.org/wiki/BaseSixtyFour
------------------------------------------------------------------------------------------------------------------------
-- Lua 5.1+ base64 v3.0 (c) 2009 by Alex Kloss <alexthkloss@web.de>
-- licensed under the terms of the LGPL2

-- character table string
local b = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'

-- encoding
function encode_base64(data)
    return ((data:gsub('.', function(x)
        local r, b = '', x:byte()
        for i = 8, 1, -1 do
            r = r .. (b % 2 ^ i - b % 2 ^ (i - 1) > 0 and '1' or '0')
        end
        return r;
    end) .. '0000'):gsub('%d%d%d?%d?%d?%d?', function(x)
        if (#x < 6) then
            return ''
        end
        local c = 0
        for i = 1, 6 do
            c = c + (x:sub(i, i) == '1' and 2 ^ (6 - i) or 0)
        end
        return b:sub(c + 1, c + 1)
    end) .. ({ '', '==', '=' })[#data % 3 + 1])
end

-- decoding
function decode_base64(data)
    data = string.gsub(data, '[^' .. b .. '=]', '')
    return (data:gsub('.', function(x)
        if (x == '=') then
            return ''
        end
        local r, f = '', (b:find(x) - 1)
        for i = 6, 1, -1 do
            r = r .. (f % 2 ^ i - f % 2 ^ (i - 1) > 0 and '1' or '0')
        end
        return r;
    end)        :gsub('%d%d%d?%d?%d?%d?%d?%d?', function(x)
        if (#x ~= 8) then
            return ''
        end
        local c = 0
        for i = 1, 8 do
            c = c + (x:sub(i, i) == '1' and 2 ^ (8 - i) or 0)
        end
        return string.char(c)
    end))
end


------------------------------------------------------------------------------------------------------------------------
--- Logger
------------------------------------------------------------------------------------------------------------------------

------------------------------------------------------------------------------------------------------------------------
local debug = function(message)
    print('[DEBUG] - ' .. message)
end

local info = function(message)
    print('[INFO] - ' .. message)
end

local error = function(message)
    print('[ERROR - ' .. message)
end

local function dumpt(t)
    if type(t) == 'table' then
        local s = '{ '
        for k, v in pairs(t) do
            if type(k) ~= 'number' then
                k = '"' .. k .. '"'
            end
            s = s .. '[' .. k .. '] = ' .. dumpt(v) .. ','
        end
        return s .. '} '
    else
        return tostring(t)
    end
end

------------------------------------------------------------------------------------------------------------------------
--- Url
--- https://developer.mozilla.org/en-US/docs/Learn/Common_questions/What_is_a_URL
------------------------------------------------------------------------------------------------------------------------

------------------------------------------------------------------------------------------------------------------------
--- Parses the given url and returns a URL table
---
--- `{ parameters={sort="asc", size=20}, path="/employees" }`
---
--- @param original_url string - The Original Request URL i.e. `/employees?sort=asc&size=20`
--- @return string, table Returns the path part alongside a table of parsed parameters
---
local function parse_url(original_url)
    local resource_path, parameters = original_url:match('(.+)?(.*)')
    if (parameters) then
        local params = {}
        for parameter in string.gmatch(parameters, "[^&]+") do
            local name, value = parameter:match('(.+)=(.+)')
            params[name] = value
        end

        return resource_path, params
    end
    return original_url
end


------------------------------------------------------------------------------------------------------------------------
--- Validations
------------------------------------------------------------------------------------------------------------------------

------------------------------------------------------------------------------------------------------------------------
--- Checks if the given port is a valid number between the range of 1023 and 65353
--- @param port number Proposed port
--- @return boolean If the given value is a valid port
local function isPort(port)
    return type(port) == "number" and port >= 1023 and port <= 65353
end

------------------------------------------------------------------------------------------------------------------------
--- HTTP Auth
------------------------------------------------------------------------------------------------------------------------

local BASIC = "Basic"
local BEARER_TOKEN = "Bearer Token"
local API_KEY = "Api Key"

------------------------------------------------------------------------------------------------------------------------
--- Provides the basic authorisation headers from the given authconfig
---
--- @param authconfig table auth authconfig table
--- @return table Table of headers that should be verified match the request headers
local function basic(authconfig)
    assert(authconfig.username and type(authconfig.username) == "string", "username is required if Basic auth is enabled")
    assert(authconfig.password and type(authconfig.password) == "string", "password is required if Basic auth is enabled")
    return { Authorization = "Basic " .. encode_base64(authconfig.username .. ":" .. authconfig.password) }
end

------------------------------------------------------------------------------------------------------------------------
--- Provides the Bearer Token headers from the given authconfig
--- @param authconfig table auth authconfig table
--- @return table Table of headers that should be verified match the request headers
local function bearer_token(authconfig)
    assert(authconfig.token and type(authconfig.token) == "string", "token is required if Bearer Token auth is enabled")
    return { Authorization = "Bearer " .. authconfig.token }
end

------------------------------------------------------------------------------------------------------------------------
--- Provides the API Key headers from the given authconfig
--- @param authconfig table auth authconfig table
--- @return table Table of headers that should be verified match the request headers
local function api_key(authconfig)
    assert(authconfig.key and type(authconfig.key) == "string", "key is required if Api Key auth is enabled")
    assert(authconfig.value and type(authconfig.value) == "string", "value is required if Api Key auth is enabled")
    return { [authconfig.key] = authconfig.value }
end

------------------------------------------------------------------------------------------------------------------------
--- Gets the associated auth headers based off the given auth authconfig
--- @param authconfig table auth authconfig table
--- @return table Table of headers that should be verified match the request headers
local function get_auth_headers(authconfig)
    assert(authconfig.type == BASIC or authconfig.type == BEARER_TOKEN or authconfig.type == API_KEY, string.format("Invalid auth type, expected one of '%s', '%s', '%s'", BASIC, BEARER_TOKEN, API_KEY))

    if authconfig.type == BASIC then
        return basic(authconfig)
    elseif authconfig.type == BEARER_TOKEN then
        return bearer_token(authconfig)
    elseif authconfig.type == API_KEY then
        return api_key(authconfig)
    end
end


------------------------------------------------------------------------------------------------------------------------
--- HTTP Receiver
------------------------------------------------------------------------------------------------------------------------

------------------------------------------------------------------------------------------------------------------------
--- Reads HTTP Message from the given connection
---
--- @see https://developer.mozilla.org/en-US/docs/Web/HTTP/Messages
--- @param client client @see https://lunarmodules.github.io/luasocket/tcp.html
--- @param match_headers table headers table that needs to match exactly to proceed to get body
--- @return table, number Request table containing method, original_url, protocol, path, parameters, body, headers. Optionally returns a second item representing an error_code from the match_headers failing
local function receive_http(client, match_headers)
    local request = { headers = {} }

    debug("receiving start-line")
    local received, err = client:receive()

    if (err) then
        error("Failed to get start-line due to " .. err)
        return
    end

    debug("parsing start-line")
    local method, original_url, protocol = string.match(received, "(%S+) (%S+) (%S+)")
    request.method = method
    request.original_url = original_url
    request.protocol = protocol

    debug("parsing url")
    local path, parameters = parse_url(original_url)
    request.path = path
    request.parameters = parameters

    debug("receiving headers")
    while 1 do
        local header, err = client:receive()
        if (err) then
            error("Error while receiving headers " .. err)
            break
        end
        if (header == "") then
            break
        end
        local header, value = string.match(header, "(.+): (.+)")
        request.headers[header] = value
    end

    debug("ensuring match headers")
    for k, v in pairs(match_headers) do
        if (request.headers[k] ~= v.value) then
            info("Match header failed, returning " .. v.error_code)
            return request, v.error_code -- Immediately fail with error code on match error
        end
    end

    debug("checking for content-length header")
    local content_length = request.headers["Content-Length"]
    if (content_length and tonumber(content_length) > 0) then
        debug("Found content-length header, receiving body")
        local body, err = client:receive(content_length)

        request.body = body

        if (err) then
            error("Failed to get body due to " .. err)
        end
    end

    debug("request completed")
    return request
end

------------------------------------------------------------------------------------------------------------------------
--- HTTP Sender
------------------------------------------------------------------------------------------------------------------------

local EMPTY_LINE = ""
local CRLF = "\r\n"

local status_text = {
    [100] = "Continue",
    [101] = "Switching protocols",
    [102] = "Processing",
    [103] = "Early Hints",
    [200] = "OK",
    [201] = "Created",
    [202] = "Accepted",
    [203] = "	Non-Authoritative Information",
    [204] = "No Content",
    [205] = "Reset Content",
    [206] = "Partial Content",
    [207] = "Multi-Status",
    [208] = "Already Reported",
    [226] = "IM Used",
    [300] = "Multiple Choices",
    [301] = "Moved Permanently",
    [302] = "Found (Previously \"Moved Temporarily\")",
    [303] = "See Other",
    [304] = "Not Modified",
    [305] = "Use Proxy",
    [306] = "Switch Proxy",
    [307] = "Temporary Redirect",
    [308] = "Permanent Redirect",
    [400] = "Bad Request",
    [401] = "Unauthorized",
    [402] = "Payment Required",
    [403] = "Forbidden",
    [404] = "Not Found",
    [405] = "Method Not Allowed",
    [406] = "Not Acceptable",
    [407] = "Proxy Authentication Required",
    [408] = "Request Timeout",
    [409] = "Conflict",
    [410] = "Gone",
    [411] = "Length Required",
    [412] = "Precondition Failed",
    [413] = "Payload Too Large",
    [414] = "URI Too Long",
    [415] = "Unsupported Media Type",
    [416] = "Range Not Satisfiable",
    [417] = "Expectation Failed",
    [418] = "I'm a Teapot",
    [421] = "Misdirected Request",
    [422] = "Unprocessable Entity",
    [423] = "Locked",
    [424] = "Failed Dependency",
    [425] = "Too Early",
    [426] = "Upgrade Required",
    [428] = "Precondition Required",
    [429] = "Too Many Requests",
    [431] = "Request Header Fields Too Large",
    [451] = "Unavailable For Legal Reasons",
    [500] = "Internal Server Error",
    [501] = "Not Implemented",
    [502] = "Bad Gateway",
    [503] = "Service Unavailable",
    [504] = "Gateway Timeout",
    [505] = "HTTP Version Not Supported",
    [506] = "Variant Also Negotiates",
    [507] = "Insufficient Storage",
    [508] = "Loop Detected",
    [510] = "Not Extended",
    [511] = "Network Authentication Required"
}

------------------------------------------------------------------------------------------------------------------------
--- Writes HTTP Message to the given connection using the given response object
---
--- @see https://developer.mozilla.org/en-US/docs/Web/HTTP/Messages
--- @param client client @see https://lunarmodules.github.io/luasocket/tcp.html
--- @param response table response table containing 'status' and 'body'
local function send_http(client, response)
    info("Building HTTP Response" .. dumpt(response))

    local start_line = table.concat({ "HTTP/1.1", response.status, status_text[response.status] }, " ")

    local headers = { "Server: Lua HTTP/1.1" }
    for name, value in pairs(response.headers) do
        table.insert(headers, name .. ": " .. value)
    end

    local response_string
    if (response.body) then
        response_string = table.concat({ start_line, table.concat(headers, CRLF), EMPTY_LINE, response.body }, CRLF)
    else
        response_string = table.concat({ start_line, table.concat(headers, CRLF), EMPTY_LINE, EMPTY_LINE }, CRLF)
    end

    info("Sending HTTP Response")
    info(">> " .. response_string)
    client:send(response_string)
end

------------------------------------------------------------------------------------------------------------------------
--- HTTP Server
------------------------------------------------------------------------------------------------------------------------

local handlers = {}

local OK = 200

local FORBIDDEN = 403
local NOT_FOUND = 404
local METHOD_NOT_ALLOWED = 405

local INTERNAL_SERVER_ERROR = 500

------------------------------------------------------------------------------------------------------------------------
--- Registers the handler against the method and path
---
--- @param method string HTTP Method to use the handler for
--- @param path string resource path to use the handler for
--- @param handler function Function to be invoked with request and response objects.
local use = function(method, path, handler)
    if (handlers[path]) then
        handlers[path][string.upper(method)] = handler
    else
        handlers[path] = { [string.upper(method)] = handler }
    end
end

------------------------------------------------------------------------------------------------------------------------
--- Registers the handler against the path for GET requests
---
--- @param path string resource path to use the handler for
--- @param handler function Function to be invoked with request and response objects.
local get = function(path, handler)
    use("GET", path, handler)
end

------------------------------------------------------------------------------------------------------------------------
--- Registers the handler against the path for POST requests
---
--- @param path string resource path to use the handler for
--- @param handler function Function to be invoked with request and response objects.
local post = function(path, handler)
    use("POST", path, handler)
end

------------------------------------------------------------------------------------------------------------------------
--- Primary Entrypoint for starting the HTTP server listening.
---
--- @param config table config table defining the HTTP Server configuration
local start = function(config)
    -- Overwrite the logger if impl provided
    if (config.logger) then
        assert(config.logger.info)
        assert(config.logger.error)

        info = config.logger.info
        error = config.logger.error
    end

    -- Log Handlers at startup
    for path, methods in pairs(handlers) do
        for method, handler in pairs(methods) do
            info(method .. " - " .. path)
        end
    end

    -- Validate port config
    assert(isPort(config.port), "invalid port configuration provided port must be a number between 1023 and 65353")

    local tcpServer = socket.bind(config.address, config.port)

    if not tcpServer then
        error("Error: Could not bind socket.")
    end

    local ip, port = tcpServer:getsockname()

    info("HTTP Server running on " .. ip .. ":" .. port)

    while 1 do
        local client = tcpServer:accept()
        client:settimeout(config.timeout)

        -- Dictionary of Headers that need to match, failure to match fails the read operation and returns the error code
        local match_headers = {}
        if (config.auth) then
            for header, headerValue in pairs(get_auth_headers(config.auth)) do
                match_headers[header] = { value = headerValue, error_code = FORBIDDEN }
            end
        end
        local response = { status = INTERNAL_SERVER_ERROR, headers = {} }

        local request, error_status = receive_http(client, match_headers)

        if (error_status) then
            info("Error code emitted while reading request " .. error_status)
            response.status = error_status
        end

        if (not error_status and request) then
            info("Handling Request")
            if (not handlers[request.path]) then
                info("Unhandled Path Request, sending 404")
                response.status = NOT_FOUND
            elseif (handlers[request.path] and not handlers[request.path][request.method]) then
                info("Unhandled Method Request, sending 405")
                local allow = {}
                for method, _ in pairs(handlers[request.path]) do
                    table.insert(allow, method)
                end
                response.headers.Allow = table.concat(allow, ", ")
                response.status = METHOD_NOT_ALLOWED
            else
                info("Handling Request")
                handlers[request.path][request.method](request, response)
                response.status = OK
            end

        end

        send_http(client, response)

        info("Connection Completed")
        client:close()
    end
end

return { start = start, use = use, get = get, post = post }