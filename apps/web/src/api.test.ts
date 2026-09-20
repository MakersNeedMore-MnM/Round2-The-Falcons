import { beforeEach, describe, expect, it, vi } from "vitest";
import { ApiError, api, session } from "./api";

const values = new Map<string, string>();
Object.defineProperty(globalThis, "sessionStorage", {
  configurable: true,
  value: { getItem: (key: string) => values.get(key) ?? null, setItem: (key: string, value: string) => values.set(key, value), removeItem: (key: string) => values.delete(key) },
});

describe("Cascadia frontend API boundary", () => {
  beforeEach(() => { values.clear(); vi.restoreAllMocks(); });

  it("sends the tab-scoped token and validates a real organization response", async () => {
    session.set("signed-access-token");
    const organization = { id: crypto.randomUUID(), name: "Grid Operations", sector: "energy", createdAt: "2026-08-26T12:00:00Z" };
    const fetchMock = vi.fn<typeof fetch>(async () => new Response(JSON.stringify(organization), { status: 200, headers: { "content-type": "application/json" } }));
    vi.stubGlobal("fetch", fetchMock);
    await expect(api.organization()).resolves.toEqual(organization);
    expect(fetchMock.mock.calls[0]?.[1]?.headers).toMatchObject({ authorization: "Bearer signed-access-token" });
  });

  it("rejects malformed server data instead of rendering it", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => new Response(JSON.stringify({ id: "not-a-uuid" }), { status: 200 })));
    await expect(api.organization()).rejects.toThrow();
  });

  it("preserves authorization failures as typed API errors", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => new Response(JSON.stringify({ error: "Unauthorized" }), { status: 401 })));
    const error = await api.organization().catch((reason: unknown) => reason);
    expect(error).toBeInstanceOf(ApiError);
    expect(error).toMatchObject({ status: 401, message: "Unauthorized" });
  });
});
