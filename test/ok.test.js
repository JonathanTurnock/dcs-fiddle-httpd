const { describe, beforeAll, it, expect } = require("@jest/globals");
const { OK } = require("http-status");
const { message } = require("statuses");
const axios = require("axios");

describe("GIVEN a request to a known route", () => {
  let result;

  beforeAll(async () => {
    result = await axios.get("http://127.0.0.1:3000/");
  });

  it("should have the status code", () => {
    expect(result.status).toEqual(OK);
  });

  it("should have the correct status text", () => {
    expect(result.statusText).toEqual(message[OK]);
  });

  it("should have the correct content type header", () => {
    expect(result.headers.get("content-type")).toEqual(
      "text/plain; charset=utf-8"
    );
  });

  it("should return the expected response body", async () => {
    expect(result.data).toEqual("Hello World");
  });
});
