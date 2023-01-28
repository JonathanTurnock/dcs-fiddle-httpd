local http = require("http")

http.use("GET", "/", function(request, response)
    response.body = { status = "OK", request = request }
end)

http.post("/", function(request, response)
    response.body = { status = "OK", request = request }
end)

http.get("/health", function(request, response)
    response.body = { status = "OK" }
end)

http.start({
    address = "localhost",
    port = 3000,
    timeout = 15,
    auth = {
        type = "Basic",
        username = "admin",
        password = "admin"
    }
})