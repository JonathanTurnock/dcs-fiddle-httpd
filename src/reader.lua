local logger = require("logger")
local reader = {}

local function receive(connection, length)
    local value, error = connection:receive(length)

    if (error) then
        logger.error("<< - " .. error)
        return nil
    end

    logger.info("<< - " .. value)
    return value
end

--[[
    Read HTTP Message
    https://developer.mozilla.org/en-US/docs/Web/HTTP/Messages
 ]]--
reader.read = function(connection)
    local data = {headers = {}}
    local received = receive(connection)

    if (not received) then
        return nil
    end

    -- Receive start-line
    local method, originalUrl, protocol = string.match(received, "(%S+) (%S+) (%S+)")
    data.method = method
    data.originalUrl = originalUrl
    data.protocol = protocol

    -- Receive headers until blank line
    local headers = {}
    while 1 do
        local header = receive(connection)

        if (header == "") then
            break
        end

        local header, value = string.match(header, "(%S+): (%S+)")
        headers[header] = value
    end
    data.headers = headers

    -- Receive body based on Content-Length
    local contentLength = data.headers["Content-Length"]
    if (contentLength) then
        local body = receive(connection,contentLength)
        data.body = body
    end

    return data
end

return reader