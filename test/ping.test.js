const { describe, beforeAll, it, expect } = require("@jest/globals");
const { OK } = require("http-status");
const { message } = require("statuses");
const axios = require("axios");

describe("GIVEN a request to the ping endpoint", () => {
  let result;

  beforeAll(async () => {
    result = await axios.post(
      "http://127.0.0.1:3000/ping?param1=value1&param2=value2",
      { bodyItem1: "bodyValue1" }
    );
  });

  it("should have the status code", () => {
    expect(result.status).toEqual(OK);
  });

  it("should have the correct status text", () => {
    expect(result.statusText).toEqual(message[OK]);
  });

  it("should have the correct content type header", () => {
    expect(result.headers.get("content-type")).toEqual(
      "application/json; charset=utf-8"
    );
  });

  it("should return the expected response body containing parsed query params and input body", async () => {
    expect(result.data).toEqual({
      pong: {
        body: '{"bodyItem1":"bodyValue1"}',
        headers: {
          Accept: "application/json, text/plain, */*",
          "Accept-Encoding": "gzip, compress, deflate, br",
          Connection: "close",
          "Content-Length": "26",
          "Content-Type": "application/json",
          Host: "127.0.0.1:3000",
          "User-Agent": "axios/1.2.6",
        },
        query: {
          param1: "value1",
          param2: "value2",
        },
      },
    });
  });
});
