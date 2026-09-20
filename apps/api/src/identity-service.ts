import { createHash, randomBytes } from "node:crypto";
import {
  ClientSecretPost, authorizationCodeGrant, buildAuthorizationUrl, calculatePKCECodeChallenge,
  discovery, randomNonce, randomPKCECodeVerifier, randomState, type Configuration,
} from "openid-client";
import type { AuthenticatedSession } from "@cascadia/contracts";
import type { AppConfig } from "./config.js";
import type { CascadiaStore, IdentitySessionRecord } from "./store.js";

export const productionSessionCookie = "__Host-cascadia_session";
export const developmentSessionCookie = "cascadia_session";
export const csrfCookieName = "cascadia_csrf";

export function sessionCookieName(config: AppConfig): string {
  return config.NODE_ENV === "production" ? productionSessionCookie : developmentSessionCookie;
}

export function digest(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function cleanReturnTo(value: unknown): string {
  if (typeof value !== "string" || !value.startsWith("/") || value.startsWith("//") || value.includes("\\")) return "/app";
  return value.slice(0, 500);
}

function values(csv: string): string[] {
  return csv.split(",").map((value) => value.trim()).filter(Boolean);
}

function stringArray(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((entry): entry is string => typeof entry === "string") : [];
}

export function hasVerifiedMfa(claims: Record<string, unknown>, acceptedAmrCsv: string, acceptedAcrCsv: string): boolean {
  const amr = stringArray(claims.amr);
  const acceptedAmr = values(acceptedAmrCsv);
  const acceptedAcr = values(acceptedAcrCsv);
  return amr.some((entry) => acceptedAmr.includes(entry)) || (typeof claims.acr === "string" && acceptedAcr.includes(claims.acr));
}

export function publicSession(session: IdentitySessionRecord, organization: AuthenticatedSession["organization"], csrfToken: string): AuthenticatedSession {
  return { authenticated: true, user: session.user, organization, role: session.role, mfaVerified: true, expiresAt: session.expiresAt, csrfToken };
}

export class OidcIdentityService {
  private configuration?: Promise<Configuration>;

  constructor(private readonly config: AppConfig, private readonly store: CascadiaStore) {}

  get enabled(): boolean { return Boolean(this.config.OIDC_ISSUER_URL && this.config.OIDC_CLIENT_ID && this.config.OIDC_CLIENT_SECRET); }

  private client(): Promise<Configuration> {
    if (!this.enabled) throw Object.assign(new Error("Enterprise SSO is not configured."), { statusCode: 503 });
    this.configuration ??= discovery(
      new URL(this.config.OIDC_ISSUER_URL!),
      this.config.OIDC_CLIENT_ID!,
      { redirect_uris: [this.callbackUrl], response_types: ["code"] },
      ClientSecretPost(this.config.OIDC_CLIENT_SECRET!),
    );
    return this.configuration;
  }

  get callbackUrl(): string { return new URL("/api/auth/callback", this.config.PUBLIC_APP_URL).href; }

  async begin(returnTo: unknown): Promise<URL> {
    const client = await this.client();
    const state = randomState();
    const nonce = randomNonce();
    const codeVerifier = randomPKCECodeVerifier();
    const challenge = await calculatePKCECodeChallenge(codeVerifier);
    await this.store.createOidcLoginAttempt({
      stateHash: digest(state), codeVerifier, nonce, returnTo: cleanReturnTo(returnTo),
      expiresAt: new Date(Date.now() + 10 * 60_000).toISOString(),
    });
    const parameters: Record<string, string> = {
      redirect_uri: this.callbackUrl, scope: "openid profile email", response_type: "code", state, nonce,
      code_challenge: challenge, code_challenge_method: "S256",
    };
    const acrValues = values(this.config.OIDC_MFA_ACR_VALUES);
    if (acrValues.length) parameters.acr_values = acrValues.join(" ");
    return buildAuthorizationUrl(client, parameters);
  }

  async complete(query: Record<string, unknown>): Promise<{ session: IdentitySessionRecord; token: string; csrfToken: string; returnTo: string }> {
    const state = typeof query.state === "string" ? query.state : "";
    const attempt = state ? await this.store.consumeOidcLoginAttempt(digest(state)) : undefined;
    if (!attempt) throw Object.assign(new Error("The login attempt is invalid, expired, or already used."), { statusCode: 401 });
    const callback = new URL(this.callbackUrl);
    for (const [key, value] of Object.entries(query)) if (typeof value === "string") callback.searchParams.set(key, value);
    const tokens = await authorizationCodeGrant(await this.client(), callback, {
      pkceCodeVerifier: attempt.codeVerifier, expectedState: state, expectedNonce: attempt.nonce, idTokenExpected: true,
    });
    const claims = tokens.claims();
    if (!claims || typeof claims.sub !== "string" || typeof claims.email !== "string" || claims.email_verified !== true) {
      throw Object.assign(new Error("SSO must return a verified email identity."), { statusCode: 403 });
    }
    const mfaVerified = hasVerifiedMfa(claims as Record<string, unknown>, this.config.OIDC_MFA_AMR_VALUES, this.config.OIDC_MFA_ACR_VALUES);
    if (!mfaVerified) throw Object.assign(new Error("Multi-factor authentication is required by Cascadia policy."), { statusCode: 403 });
    const identity = await this.store.resolveIdentity(this.config.OIDC_ISSUER_URL!, claims.sub, claims.email);
    if (!identity) throw Object.assign(new Error("This verified identity has not been enrolled by a Cascadia administrator."), { statusCode: 403 });
    const token = randomBytes(32).toString("base64url");
    const csrfToken = randomBytes(32).toString("base64url");
    const session = await this.store.createIdentitySession({
      ...identity, tokenHash: digest(token), csrfTokenHash: digest(csrfToken), mfaVerified: true,
      issuer: this.config.OIDC_ISSUER_URL!, subject: claims.sub,
      expiresAt: new Date(Date.now() + this.config.SESSION_TTL_MINUTES * 60_000).toISOString(),
    });
    return { session, token, csrfToken, returnTo: attempt.returnTo };
  }
}
