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

http.start({
    address = "127.0.0.1",
    port = 3000,
    timeout = 15
})