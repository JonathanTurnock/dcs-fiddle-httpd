const { describe, beforeAll, it, expect } = require("@jest/globals");
const { NOT_FOUND } = require("http-status");
const { message } = require("statuses");
const axios = require("axios");

describe("GIVEN a request to an unknown route", () => {
  let result;

  beforeAll(async () => {
    result = await axios.get("http://127.0.0.1:3000/no-route", {
      validateStatus: false,
    });
  });

  it("should have the status code 404", () => {
    expect(result.status).toEqual(NOT_FOUND);
  });

  it("should have the status text Not Found", () => {
    expect(result.statusText).toEqual(message[NOT_FOUND]);
  });

  it("should return an empty body", async () => {
    expect(result.data).toEqual("");
  });
});
