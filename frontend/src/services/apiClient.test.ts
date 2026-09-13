import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ApiError, api, refreshAccessToken } from "./apiClient";
import { getAccessToken, setAccessToken } from "./tokenStore";

function jsonResponse(status: number, body: unknown) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

describe("ApiError message extraction", () => {
  it("uses a string detail directly", () => {
    expect(new ApiError(404, "not found").message).toBe("not found");
  });

  it("joins pydantic's list-of-objects validation detail", () => {
    const detail = [
      { loc: ["body", "email"], msg: "field required" },
      { loc: ["body", "password"], msg: "too short" },
    ];
    expect(new ApiError(422, detail).message).toBe("field required; too short");
  });

  it("reads a message field from an object detail (e.g. MFA required)", () => {
    expect(new ApiError(401, { message: "mfa code required", mfa_required: true }).message).toBe(
      "mfa code required",
    );
  });

  it("falls back to a generic message for an unrecognized shape", () => {
    expect(new ApiError(500, null).message).toBe("request failed with status 500");
  });
});

describe("apiRequest 401 handling", () => {
  beforeEach(() => {
    setAccessToken("expired-token");
  });

  afterEach(() => {
    setAccessToken(null);
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
  });

  it("refreshes once and retries on a 401, then updates the stored token", async () => {
    const calls: string[] = [];
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input);
      calls.push(url);
      if (url.includes("/auth/refresh")) {
        return jsonResponse(200, { access_token: "new-token", token_type: "bearer", expires_in: 900 });
      }
      if (url.includes("/protected")) {
        // First call (with the old token) 401s; the retry (after refresh) succeeds.
        if (calls.filter((c) => c.includes("/protected")).length === 1) {
          return jsonResponse(401, "expired");
        }
        return jsonResponse(200, { ok: true });
      }
      throw new Error(`unexpected fetch: ${url}`);
    });
    vi.stubGlobal("fetch", fetchMock);

    const result = await api.get<{ ok: boolean }>("/protected");

    expect(result).toEqual({ ok: true });
    expect(getAccessToken()).toBe("new-token");
    expect(calls.filter((c) => c.includes("/protected"))).toHaveLength(2);
    expect(calls.filter((c) => c.includes("/auth/refresh"))).toHaveLength(1);
  });

  it("clears the stored token and surfaces the 401 when refresh itself fails", async () => {
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url.includes("/auth/refresh")) return jsonResponse(401, "invalid refresh token");
      return jsonResponse(401, "expired");
    });
    vi.stubGlobal("fetch", fetchMock);

    await expect(api.get("/protected")).rejects.toBeInstanceOf(ApiError);
    expect(getAccessToken()).toBeNull();
  });
});

describe("refreshAccessToken", () => {
  afterEach(() => {
    setAccessToken(null);
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
  });

  it("returns false without throwing when the refresh call itself errors", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => {
        throw new Error("network down");
      }),
    );
    await expect(refreshAccessToken()).resolves.toBe(false);
  });
});
