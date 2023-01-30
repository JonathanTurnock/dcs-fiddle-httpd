local http = require("http")
local json = require("json")

http.use("GET", "/", function(request, response)
    response.headers["Content-Type"] = "text/plain; charset=utf-8"
    response.body = "Hello World"
end)

http.post("/ping", function(request, response)
    response.headers["Content-Type"] = "application/json; charset=utf-8"
    response.body = json.encode({ pong = {query=request.parameters,body=request.body,headers=request.headers} })
end)

http.get("/health", function(request, response)
    response.headers["Content-Type"] = "application/json; charset=utf-8"
    response.body = json.encode({ status = "UP" })
end)

local server_loop = http.create_server({
    address = "127.0.0.1",
    port = 3000
})

while 1 do -- attach to some kind of timer as to not block
    server_loop()
end
