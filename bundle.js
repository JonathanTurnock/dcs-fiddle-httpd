const { bundle } = require("luabundle");
const { resolve } = require("path");
const { z } = require("zod");

console.log(process.env.LUA_PATH);

const { LUA_PATH } = z
  .object({
    LUA_PATH: z.string().transform((it) => it.split(";")),
  })
  .parse(process.env);

console.log(LUA_PATH);

console.log(
  bundle(resolve(__dirname, "src/init.lua"), {
    luaVersion: "5.1",
    paths: [...LUA_PATH, resolve(__dirname, "lua_modules/?.lua"), resolve(__dirname, "src/?.lua")],
  })
);
