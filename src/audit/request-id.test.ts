import { describe, it, expect } from "vitest";
import { createRequestId } from "./request-id.js";

const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

describe("createRequestId", () => {
  it("returns a UUID-shaped string", () => {
    const id = createRequestId();
    expect(id).toMatch(UUID_PATTERN);
  });

  it("returns different values on consecutive calls", () => {
    expect(createRequestId()).not.toBe(createRequestId());
  });
});
