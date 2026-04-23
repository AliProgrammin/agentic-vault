import { describe, expect, it } from "vitest";
import { parseSgrMouse } from "./mouse.js";

describe("parseSgrMouse", () => {
  it("parses a left-press event with full ESC prefix", () => {
    expect(parseSgrMouse("\x1b[<0;5;1M")).toEqual({
      kind: "press",
      button: "left",
      col: 5,
      row: 1,
    });
  });

  it("parses a left-press event after Ink stripped the ESC prefix", () => {
    expect(parseSgrMouse("[<0;5;1M")).toEqual({
      kind: "press",
      button: "left",
      col: 5,
      row: 1,
    });
  });

  it("parses a left-release event (lowercase terminator)", () => {
    expect(parseSgrMouse("[<0;5;1m")).toEqual({
      kind: "release",
      button: "left",
      col: 5,
      row: 1,
    });
  });

  it("parses middle and right press events", () => {
    expect(parseSgrMouse("[<1;3;4M")).toMatchObject({ kind: "press", button: "middle" });
    expect(parseSgrMouse("[<2;3;4M")).toMatchObject({ kind: "press", button: "right" });
  });

  it("parses scroll up (cb=64)", () => {
    expect(parseSgrMouse("[<64;12;7M")).toEqual({
      kind: "scrollUp",
      button: "none",
      col: 12,
      row: 7,
    });
  });

  it("parses scroll down (cb=65)", () => {
    expect(parseSgrMouse("[<65;12;7M")).toEqual({
      kind: "scrollDown",
      button: "none",
      col: 12,
      row: 7,
    });
  });

  it("returns null for non-mouse escape sequences", () => {
    expect(parseSgrMouse("[A")).toBeNull();       // up arrow
    expect(parseSgrMouse("[1;5C")).toBeNull();     // modified arrow
    expect(parseSgrMouse("")).toBeNull();
    expect(parseSgrMouse("hello")).toBeNull();
    expect(parseSgrMouse("\x1b")).toBeNull();
  });

  it("returns null for malformed / partial mouse sequences without throwing", () => {
    expect(parseSgrMouse("[<")).toBeNull();
    expect(parseSgrMouse("[<0;5")).toBeNull();
    expect(parseSgrMouse("[<0;5;1")).toBeNull();
    expect(parseSgrMouse("[<abc;5;1M")).toBeNull();
    expect(parseSgrMouse("[<0;5;1X")).toBeNull();
  });
});
