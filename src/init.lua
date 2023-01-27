local logger = require("logger")
local config = require("config")
local reader = require("reader")
local socket = require("socket").bind("localhost", 17234)
local f = string.format

if not socket then
    logger.error("Error: Could not bind socket.\n")
end

local ip, port = socket:getsockname()

logger.info(f("Listening to %s:%s", ip, port))

function dump(o)
    if type(o) == 'table' then
        local s = '{ '
        for k,v in pairs(o) do
            if type(k) ~= 'number' then k = '"'..k..'"' end
            s = s .. '['..k..'] = ' .. dump(v) .. ','
        end
        return s .. '} '
    else
        return tostring(o)
    end
end

while 1 do
    logger.info("Waiting for connection...")
    local connection = socket:accept()
    connection:settimeout(config.DEFAULT_TIMEOUT)
    local request = reader.read(connection)
    if (request) then
        logger.info("Handling Request" .. dump(request))
    end
    logger.info("Connection Completed")
    connection:close()
end

--local req, err = client:receive()
--if err then
--
--else
--    local method, originalUrl = req:gmatch("(%S+) (%S+) (%S+)")()
--
--    if (method ~= "POST") then
--        client:send("HTTP/1.1 405 Method Not Allowed\r\nContent-type: application/json\r\n\r\n{\"error\": \"405 Method Not Allowed\"}")
--    else
--        local request = { method = method, originalUrl = originalUrl }
--
--        logger.info(f("[Request] Method: %s, Url: %s:%s%s", method, ip, port, originalUrl))
--
--        client:send("HTTP/1.1 200 OK\r\nContent-type: application/json\r\n\r\n {\"hello\": \"world\"}\n")
--    end
--end
