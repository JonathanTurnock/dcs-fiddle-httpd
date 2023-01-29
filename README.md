![Tests](https://github.com/github/docs/actions/workflows/test.yml/badge.svg)

## lua-httpd

HTTP/1.1 compliant server for LUA, useful to run in game environments where a hook into the game runtime is required

It uses Javascript and Jest for unit testing and running `npm run test:watch` will allow development with automatic test being run on all changes.

> This server has a single dependency, `socket` this should be present in most game environments hopefully, however if not this will need be resolved

## Usage

The HTTP module sets up a TCP socket and listens for incoming connections.

It implements the HTTP/1.1 protocol along with provision for static configuration of Basic, Api Token and Bearer Token auth.

> It does not support cryptography or encryption.
>
> If required at a basic level this could be added within the HTTP/1.1 protocol just note the HTTP traffic (url, headers etc) would not be encrypted.
>
> An example would be to use AES encryption on post request bodies that only the client and server understand and the text is

Simply grab the `http.lua` file and as long as the `socket` library is available it should work.

See the `src/init.lua` as an example of usage, note the `json.lua` is optional and used for demonstration

## API

### Basic text

To setup a basic text endpoint define a handler, and start listening.

```lua
local http = require("http")

http.get("/", function(request, response)
    response.body = "OK"
end)

http.start({
    address = "localhost",
    port = 80,
    timeout = 15
})
```

Sending a simple request will give OK

```shell
➜  ~ curl --location --request GET 'http://localhost:3000/'
OK
```

> The default response status code is 200, if not overridden this will be the response code.

### JSON Response

There is little assistance in terms of what convenience there is on top of the basic HTTP/1.1 server.

Here is an example of using a JSON module to serve content as an API

```lua
local http = require("http")

http.get("/", function(request, response)
    response.headers["Content-Type"] = "application/json"
    response.body = json.encode({status="OK"})
end)

http.start({
    address = "localhost",
    port = 3000,
    timeout = 15
})
```

```shell
➜  ~ curl -f -i --location --request GET 'http://localhost:3000/'
HTTP/1.1 200
Server: Lua HTTP/1.1
Content-Type: application/json

{"status":"OK"}
```

> See json.lua for encoding tables as a json string https://github.com/rxi/json.lua/blob/master/json.lua

### Query Params

Query params are automatically parsed and added to the request object

Here is an example of an endpoint illustrating this

```lua
local http = require("http")

http.get("/", function(request, response)
    response.headers["Content-Type"] = "application/json"
    response.body = json.encode({status="OK", queryParams=request.query})
end)

http.start({
    address = "localhost",
    port = 3000,
    timeout = 15
})
```

```shell
➜  ~ curl -f -i --location --request GET 'http://localhost:3000?sort=asc&size=20'
HTTP/1.1 200
Server: Lua HTTP/1.1
Content-Type: application/json

{"queryParams":{"size":"20","sort":"asc"},"status":"OK"}
```

### POST

Post bodies are automatically added to the request object as plain text strings, they should be parsed to be used (i.e. if json)

```lua
local http = require("http")

http.post("/", function(request, response)
    response.headers["Content-Type"] = "application/json"

    local newEmployee = json.decode(request.body)
    newEmployee.id = 1

    response.body = json.encode(newEmployee)
end)

http.start({
    address = "localhost",
    port = 3000,
    timeout = 15
})
```

```shell
➜  ~ curl -f -i --location --request POST 'http://localhost:3000' -d '{"name":"john doe"}'

HTTP/1.1 200
Server: Lua HTTP/1.1
Content-Type: application/json

{"id":1,"name":"john doe"}
```

## Alternative HTTP Verbs

All examples above use the functions `http.get` or `http.post`, these are simply convenience and wrap the underlying `http.use`

```lua
local http = require("http")

http.use("GET", "/", function(request, response)
    response.body = "OK"
end)

http.start({
    address = "localhost",
    port = 3000,
    timeout = 15
})
```

## Authorisation

The implementation supports 3 HTTP/1.1 spec auth mechanisms.

> ⚠️ It should be noted this is NOT https, the data between the client and server is NOT encrypted, so anyone can read
> the credentials. If you are operating within an untrusted network this should absolutely not be used as a server.
>
> This is simply to avoid exposing the server to simple scans where a bad actor can find it completely unsecured.

To get setup with global auth simply define an auth table inside the config, here we use basic and specify a username and password

```lua
local http = require("http")

http.get("/", function(request, response)
    response.body = "OK"
end)

http.start({
    address = "localhost",
    port = 3000,
    timeout = 15,
    auth={
        type="Basic",
        username="admin",
        password="password123!"
    }
})
```

### Basic

Basic Auth requires the auth config to contain the following values

- **type** - `Basic` indicates basic auth impl should be used
- **username** - `string` the username to be used
- **type** - `string` the password to be used

If we now call the server without any Auth, it will fail with a 403

```shell
➜  ~ curl -f --location --request GET 'http://localhost:3000/'
curl: (22) The requested URL returned error: 403
```

Add the user information to see it succeed

```shell
➜  ~ curl -f -u admin:password123! --location --request GET 'http://localhost:3000/'
OK
```

> Basic authorization is sent as a header, the Authorization header is populated with the string  
> `Basic {username:password}` but the username:password is base64 encoded.
>
> You can implement a route/user/session specific implementation by inspecting the request.headers table in the handler.
>
> https://developer.mozilla.org/en-US/docs/Web/HTTP/Authentication#basic_authentication_scheme

### Api Key

Api Key Auth requires the auth config to contain the following values

- **type** - `Api Key` indicates api key impl should be used
- **key** - `string` the header to be used
- **value** - `string` the value to be considered authenticated

This is a very simple plain text way of authenticating using a custom header and value.

Here we have an example of using the api-key header `x-my-app-key` and a value of `pviDlowxBn`

```lua
local http = require("http")

http.get("/", function(request, response)
    response.body = "OK"
end)

http.start({
    address = "localhost",
    port = 3000,
    timeout = 15,
    auth={
        type="Api Key",
        key="x-my-app-key",
        value="pviDlowxBn"
    }
})
```

Provide the header in requests to successfully authenticate

```shell
➜  ~ curl -f --header 'x-my-app-key: pviDlowxBn' --location --request GET 'http://localhost:3000/'
OK
```

### Bearer Token

Bearer Token Auth requires the auth config to contain the following values

> This is a somewhat naive impl of the bearer token, traditionally this is used as part of an authentication process
> where the token is provided to indicate the user is already logged in. Consider using Basic or Api Key first.
>
> To see more about Bearer token usage see https://datatracker.ietf.org/doc/html/rfc6750

- **type** - `Bearer Token` indicates Bearer Token impl should be used
- **token** - `string` the token to allow access

```lua
local http = require("http")

http.get("/", function(request, response)
    response.body = "OK"
end)

http.start({
    address = "localhost",
    port = 3000,
    timeout = 15,
    auth={
        type="Bearer Token",
        token="pviDlowxBn"
    }
})
```

Here we can see the token is passed in as part of the Authorization header in the format `Bearer {token}`

```shell
➜  ~ curl -f --header 'Authorization: Bearer pviDlowxBn' --location --request GET 'http://localhost:3000/'
OK
```

## Per Route Authorization

All auth config defined in the http.start call is applied globally.

Authentication an also be applied at a function level as the below example, simply modify the status code to 403 and return

```lua
local http = require("http")

http.get("/", function(request, response)
    if (request.headers["x-my-app-key"] ~= "pviDlowxBn") then
        response.status = 403
        return
    end

    response.body = "OK"
end)

http.start({
    address = "localhost",
    port = 3000,
    timeout = 15
})
```

## References

> Documentation about implementing the HTTP Messaging Protocol
>
> https://developer.mozilla.org/en-US/docs/Web/HTTP/Messages > https://developer.mozilla.org/en-US/docs/Web/HTTP/Authentication > https://developer.mozilla.org/en-US/docs/Web/HTTP/Authentication#basic_authentication_scheme
