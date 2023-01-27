local logger = {}

function logger.debug(message)
    print("[DEBUG] - " .. message)
end

function logger.info(message)
    print("[INFO] - " .. message)
end

function logger.error(message)
    print("[ERROR] - ".. message)
end

return logger