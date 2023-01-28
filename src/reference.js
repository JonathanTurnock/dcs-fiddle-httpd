const express = require("express");
const { NOT_FOUND } = require("http-status");

const app = express();

app.get("/", (req, res) => {
  res.setHeader("content-type", "text/plain; charset=utf-8");
  res.send("Hello World");
});

app.post("/ping", (req, res) => {
  const { body, headers, query } = req;
  res.json({ pong: { query, headers, body } });
});

app.get("/health", (req, res) => {
  res.json({ status: "UP" });
});

app.use((req, res) => {
  res.status(NOT_FOUND).send();
});

app.listen(3000);
