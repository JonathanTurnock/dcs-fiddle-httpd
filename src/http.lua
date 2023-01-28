local socket = require("socket")

------------------------------------------------------------------------------------------------------------------------
--- JSON
--- @see https://github.com/rxi/json.lua/blob/master/json.lua
------------------------------------------------------------------------------------------------------------------------

--
-- json.lua
--
-- Copyright (c) 2020 rxi
--
-- Permission is hereby granted, free of charge, to any person obtaining a copy of
-- this software and associated documentation files (the "Software"), to deal in
-- the Software without restriction, including without limitation the rights to
-- use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
-- of the Software, and to permit persons to whom the Software is furnished to do
-- so, subject to the following conditions:
--
-- The above copyright notice and this permission notice shall be included in all
-- copies or substantial portions of the Software.
--
-- THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
-- IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
-- FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
-- AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
-- LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
-- OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
-- SOFTWARE.
--

local json = { _version = "0.1.2" }

-------------------------------------------------------------------------------
-- Encode
-------------------------------------------------------------------------------

local encode

local escape_char_map = {
    ["\\"] = "\\",
    ["\""] = "\"",
    ["\b"] = "b",
    ["\f"] = "f",
    ["\n"] = "n",
    ["\r"] = "r",
    ["\t"] = "t",
}

local escape_char_map_inv = { ["/"] = "/" }
for k, v in pairs(escape_char_map) do
    escape_char_map_inv[v] = k
end

local function escape_char(c)
    return "\\" .. (escape_char_map[c] or string.format("u%04x", c:byte()))
end

local function encode_nil(val)
    return "null"
end

local function encode_table(val, stack)
    local res = {}
    stack = stack or {}

    -- Circular reference?
    if stack[val] then
        error("circular reference")
    end

    stack[val] = true

    if rawget(val, 1) ~= nil or next(val) == nil then
        -- Treat as array -- check keys are valid and it is not sparse
        local n = 0
        for k in pairs(val) do
            if type(k) ~= "number" then
                error("invalid table: mixed or invalid key types")
            end
            n = n + 1
        end
        if n ~= #val then
            error("invalid table: sparse array")
        end
        -- Encode
        for i, v in ipairs(val) do
            table.insert(res, encode(v, stack))
        end
        stack[val] = nil
        return "[" .. table.concat(res, ",") .. "]"

    else
        -- Treat as an object
        for k, v in pairs(val) do
            if type(k) ~= "string" then
                error("invalid table: mixed or invalid key types")
            end
            table.insert(res, encode(k, stack) .. ":" .. encode(v, stack))
        end
        stack[val] = nil
        return "{" .. table.concat(res, ",") .. "}"
    end
end

local function encode_string(val)
    return '"' .. val:gsub('[%z\1-\31\\"]', escape_char) .. '"'
end

local function encode_number(val)
    -- Check for NaN, -inf and inf
    if val ~= val or val <= -math.huge or val >= math.huge then
        error("unexpected number value '" .. tostring(val) .. "'")
    end
    return string.format("%.14g", val)
end

local type_func_map = {
    ["nil"] = encode_nil,
    ["table"] = encode_table,
    ["string"] = encode_string,
    ["number"] = encode_number,
    ["boolean"] = tostring,
}

encode = function(val, stack)
    local t = type(val)
    local f = type_func_map[t]
    if f then
        return f(val, stack)
    end
    error("unexpected type '" .. t .. "'")
end

function json.encode(val)
    return (encode(val))
end


-------------------------------------------------------------------------------
-- Decode
-------------------------------------------------------------------------------

local parse

local function create_set(...)
    local res = {}
    for i = 1, select("#", ...) do
        res[select(i, ...)] = true
    end
    return res
end

local space_chars = create_set(" ", "\t", "\r", "\n")
local delim_chars = create_set(" ", "\t", "\r", "\n", "]", "}", ",")
local escape_chars = create_set("\\", "/", '"', "b", "f", "n", "r", "t", "u")
local literals = create_set("true", "false", "null")

local literal_map = {
    ["true"] = true,
    ["false"] = false,
    ["null"] = nil,
}

local function next_char(str, idx, set, negate)
    for i = idx, #str do
        if set[str:sub(i, i)] ~= negate then
            return i
        end
    end
    return #str + 1
end

local function decode_error(str, idx, msg)
    local line_count = 1
    local col_count = 1
    for i = 1, idx - 1 do
        col_count = col_count + 1
        if str:sub(i, i) == "\n" then
            line_count = line_count + 1
            col_count = 1
        end
    end
    error(string.format("%s at line %d col %d", msg, line_count, col_count))
end

local function codepoint_to_utf8(n)
    -- http://scripts.sil.org/cms/scripts/page.php?site_id=nrsi&id=iws-appendixa
    local f = math.floor
    if n <= 0x7f then
        return string.char(n)
    elseif n <= 0x7ff then
        return string.char(f(n / 64) + 192, n % 64 + 128)
    elseif n <= 0xffff then
        return string.char(f(n / 4096) + 224, f(n % 4096 / 64) + 128, n % 64 + 128)
    elseif n <= 0x10ffff then
        return string.char(f(n / 262144) + 240, f(n % 262144 / 4096) + 128,
                f(n % 4096 / 64) + 128, n % 64 + 128)
    end
    error(string.format("invalid unicode codepoint '%x'", n))
end

local function parse_unicode_escape(s)
    local n1 = tonumber(s:sub(1, 4), 16)
    local n2 = tonumber(s:sub(7, 10), 16)
    -- Surrogate pair?
    if n2 then
        return codepoint_to_utf8((n1 - 0xd800) * 0x400 + (n2 - 0xdc00) + 0x10000)
    else
        return codepoint_to_utf8(n1)
    end
end

local function parse_string(str, i)
    local res = ""
    local j = i + 1
    local k = j

    while j <= #str do
        local x = str:byte(j)

        if x < 32 then
            decode_error(str, j, "control character in string")

        elseif x == 92 then
            -- `\`: Escape
            res = res .. str:sub(k, j - 1)
            j = j + 1
            local c = str:sub(j, j)
            if c == "u" then
                local hex = str:match("^[dD][89aAbB]%x%x\\u%x%x%x%x", j + 1)
                        or str:match("^%x%x%x%x", j + 1)
                        or decode_error(str, j - 1, "invalid unicode escape in string")
                res = res .. parse_unicode_escape(hex)
                j = j + #hex
            else
                if not escape_chars[c] then
                    decode_error(str, j - 1, "invalid escape char '" .. c .. "' in string")
                end
                res = res .. escape_char_map_inv[c]
            end
            k = j + 1

        elseif x == 34 then
            -- `"`: End of string
            res = res .. str:sub(k, j - 1)
            return res, j + 1
        end

        j = j + 1
    end

    decode_error(str, i, "expected closing quote for string")
end

local function parse_number(str, i)
    local x = next_char(str, i, delim_chars)
    local s = str:sub(i, x - 1)
    local n = tonumber(s)
    if not n then
        decode_error(str, i, "invalid number '" .. s .. "'")
    end
    return n, x
end

local function parse_literal(str, i)
    local x = next_char(str, i, delim_chars)
    local word = str:sub(i, x - 1)
    if not literals[word] then
        decode_error(str, i, "invalid literal '" .. word .. "'")
    end
    return literal_map[word], x
end

local function parse_array(str, i)
    local res = {}
    local n = 1
    i = i + 1
    while 1 do
        local x
        i = next_char(str, i, space_chars, true)
        -- Empty / end of array?
        if str:sub(i, i) == "]" then
            i = i + 1
            break
        end
        -- Read token
        x, i = parse(str, i)
        res[n] = x
        n = n + 1
        -- Next token
        i = next_char(str, i, space_chars, true)
        local chr = str:sub(i, i)
        i = i + 1
        if chr == "]" then
            break
        end
        if chr ~= "," then
            decode_error(str, i, "expected ']' or ','")
        end
    end
    return res, i
end

local function parse_object(str, i)
    local res = {}
    i = i + 1
    while 1 do
        local key, val
        i = next_char(str, i, space_chars, true)
        -- Empty / end of object?
        if str:sub(i, i) == "}" then
            i = i + 1
            break
        end
        -- Read key
        if str:sub(i, i) ~= '"' then
            decode_error(str, i, "expected string for key")
        end
        key, i = parse(str, i)
        -- Read ':' delimiter
        i = next_char(str, i, space_chars, true)
        if str:sub(i, i) ~= ":" then
            decode_error(str, i, "expected ':' after key")
        end
        i = next_char(str, i + 1, space_chars, true)
        -- Read value
        val, i = parse(str, i)
        -- Set
        res[key] = val
        -- Next token
        i = next_char(str, i, space_chars, true)
        local chr = str:sub(i, i)
        i = i + 1
        if chr == "}" then
            break
        end
        if chr ~= "," then
            decode_error(str, i, "expected '}' or ','")
        end
    end
    return res, i
end

local char_func_map = {
    ['"'] = parse_string,
    ["0"] = parse_number,
    ["1"] = parse_number,
    ["2"] = parse_number,
    ["3"] = parse_number,
    ["4"] = parse_number,
    ["5"] = parse_number,
    ["6"] = parse_number,
    ["7"] = parse_number,
    ["8"] = parse_number,
    ["9"] = parse_number,
    ["-"] = parse_number,
    ["t"] = parse_literal,
    ["f"] = parse_literal,
    ["n"] = parse_literal,
    ["["] = parse_array,
    ["{"] = parse_object,
}

parse = function(str, idx)
    local chr = str:sub(idx, idx)
    local f = char_func_map[chr]
    if f then
        return f(str, idx)
    end
    decode_error(str, idx, "unexpected character '" .. chr .. "'")
end

function json.decode(str)
    if type(str) ~= "string" then
        error("expected argument of type string, got " .. type(str))
    end
    local res, idx = parse(str, next_char(str, 1, space_chars, true))
    idx = next_char(str, idx, space_chars, true)
    if idx <= #str then
        decode_error(str, idx, "trailing garbage")
    end
    return res
end

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

        if (request.headers["Content-Type"] == "application/json") then
            request.body = json.decode(body)
        else
            request.body = body
        end

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

local CRLF = "\r\n"

------------------------------------------------------------------------------------------------------------------------
--- Writes HTTP Message to the given connection using the given response object
---
--- @see https://developer.mozilla.org/en-US/docs/Web/HTTP/Messages
--- @param client client @see https://lunarmodules.github.io/luasocket/tcp.html
--- @param response table response table containing 'status' and 'body'
local function send_http(client, response)
    info("Building HTTP Response" .. dumpt(response))
    local start_line = "HTTP/1.1 " .. response.status .. CRLF


    local body_string = ""
    if (response.body) then
        if (type(response.body) == "table") then
            response.headers["Content-Type"] = "application/json"
            body_string = json.encode(response.body) .. CRLF
        else
            body_string = response.body .. CRLF
        end
    end

    local header_string = "Server: Lua HTTP/1.1" .. CRLF
    for name, value in pairs(response.headers) do
        header_string = header_string .. name .. ": " .. value .. CRLF
    end

    response_string = start_line .. header_string .. CRLF .. body_string .. CRLF

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