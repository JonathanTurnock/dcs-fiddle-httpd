const { describe, beforeAll, it, expect } = require("@jest/globals");
const { METHOD_NOT_ALLOWED } = require("http-status");
const { message } = require("statuses");
const axios = require("axios");

describe("GIVEN a request to a known route with unsupported method", () => {
  let result;

  beforeAll(async () => {
    result = await axios.post("http://127.0.0.1:3000/", undefined, {
      validateStatus: false,
    });
  });

  it("should have the status code 405", () => {
    expect(result.status).toEqual(METHOD_NOT_ALLOWED);
  });

  it("should have the status text Method Not Allowed", () => {
    expect(result.statusText).toEqual(message[METHOD_NOT_ALLOWED]);
  });

  it("should return an empty body", async () => {
    expect(result.data).toEqual("");
  });
});
