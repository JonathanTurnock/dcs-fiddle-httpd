## dcs-fiddle-httpd

Simple HTTP Server for DCS

## Usage

This HTTP servers sole aim to take LUA script payloads and invoke them inside DCS and return a JSON response.

It's a minimal implementation that takes a single continuous base64 encoded string in the body.

## Development

Development of this is supported by NodeJS, it uses various tools like Nodemon to
hot reload on edits etc.

It is also bundled (WIP) so it produces a single httpd.lua file that can be
installed into the game folder.

### Local Development

Run dev to start the server with hot reloading enabled

```shell
npm run dev
```

The server is running on http://localhost:17234

## Future Scope

- Support Basic Authorization in the headers

## References

> Documentation about implementing the HTTP Messaging Protocol
> 
> https://developer.mozilla.org/en-US/docs/Web/HTTP/Messages