import { z } from "zod";

const configSchema = z.object({
  NODE_ENV: z.enum(["development", "test", "production"]).default("development"),
  PORT: z.coerce.number().int().min(1).max(65535).default(3000),
  HOST: z.string().min(1).default("127.0.0.1"),
  JWT_SECRET: z.string().min(32),
  INTEGRATION_ENCRYPTION_KEY: z.string().min(32).optional(),
  DATA_STORE: z.enum(["memory", "postgres"]).default("memory"),
  DEMO_MODE: z.enum(["true", "false"]).default("false").transform((value) => value === "true"),
  DATABASE_URL: z.string().url().optional(),
  PUBLIC_APP_URL: z.string().url().default("http://127.0.0.1:5173"),
  OIDC_ISSUER_URL: z.string().url().optional(),
  OIDC_CLIENT_ID: z.string().min(1).optional(),
  OIDC_CLIENT_SECRET: z.string().min(16).optional(),
  OIDC_MFA_AMR_VALUES: z.string().default("mfa,otp,hwk,fido,webauthn"),
  OIDC_MFA_ACR_VALUES: z.string().default(""),
  SESSION_TTL_MINUTES: z.coerce.number().int().min(5).max(720).default(480),
  OBSERVABILITY_TOKEN: z.string().min(32).optional(),
  NOTIFICATION_WEBHOOK_URL: z.url().refine((value) => new URL(value).protocol === "https:", "Notification webhook URL must use HTTPS.").optional(),
  NOTIFICATION_WEBHOOK_PROVIDER: z.enum(["generic", "slack", "teams"]).optional(),
  REQUESTS_PER_MINUTE: z.coerce.number().int().min(30).max(10_000).default(300),
  SERVE_WEB: z.enum(["true", "false"]).default("false").transform((value) => value === "true"),
  WEB_DIST_DIR: z.string().min(1).default("apps/web/dist"),
  TRUST_PROXY_HOPS: z.coerce.number().int().min(0).max(3).default(0),
  MST_RPC_URL: z.string().url().default("https://testnetrpc.mstblockchain.com"),
  MST_CHAIN_ID: z.coerce.number().int().default(91562037),
  MST_DEPLOYER_PRIVATE_KEY: z.string().regex(/^0x[0-9a-fA-F]{64}$/).optional(),
  MST_CONTRACT_ADDRESS: z.string().regex(/^0x[0-9a-fA-F]{40}$/).optional(),
  MST_EXPLORER_URL: z.string().url().default("https://testnet.mstscan.com"),
  MST_CONFIRMATIONS: z.coerce.number().int().min(1).default(1),
  MST_TX_TIMEOUT_SECONDS: z.coerce.number().int().min(5).max(3600).default(120),
  MST_AUDIT_ANCHOR_INTERVAL_MINUTES: z.coerce.number().int().min(1).max(1440).default(60),
}).superRefine((config, context) => {
  if (config.DATA_STORE === "postgres" && !config.DATABASE_URL) {
    context.addIssue({ code: "custom", path: ["DATABASE_URL"], message: "DATABASE_URL is required for the PostgreSQL data store." });
  }
  if (config.NODE_ENV === "production" && config.DATA_STORE !== "postgres") {
    context.addIssue({ code: "custom", path: ["DATA_STORE"], message: "Production must use the PostgreSQL data store." });
  }
  if (config.NODE_ENV === "production" && !config.INTEGRATION_ENCRYPTION_KEY) {
    context.addIssue({ code: "custom", path: ["INTEGRATION_ENCRYPTION_KEY"], message: "Production requires a separate integration encryption key." });
  }
  const oidcValues = [config.OIDC_ISSUER_URL, config.OIDC_CLIENT_ID, config.OIDC_CLIENT_SECRET];
  if (oidcValues.some(Boolean) && !oidcValues.every(Boolean)) {
    context.addIssue({ code: "custom", path: ["OIDC_ISSUER_URL"], message: "OIDC issuer, client ID, and client secret must be configured together." });
  }
  if (config.NODE_ENV === "production" && !oidcValues.every(Boolean)) {
    context.addIssue({ code: "custom", path: ["OIDC_ISSUER_URL"], message: "Production requires an OIDC provider." });
  }
  if (config.NODE_ENV === "production" && (!config.PUBLIC_APP_URL.startsWith("https://") || !config.OIDC_ISSUER_URL?.startsWith("https://"))) {
    context.addIssue({ code: "custom", path: ["PUBLIC_APP_URL"], message: "Production application and OIDC issuer URLs must use HTTPS." });
  }
  if (config.NODE_ENV === "production" && !config.OBSERVABILITY_TOKEN) {
    context.addIssue({ code: "custom", path: ["OBSERVABILITY_TOKEN"], message: "Production requires a dedicated observability token." });
  }
});

type ParsedConfig = z.infer<typeof configSchema>;
export type AppConfig = Omit<ParsedConfig, "DEMO_MODE" | "MST_RPC_URL" | "MST_CHAIN_ID" | "MST_EXPLORER_URL" | "MST_CONFIRMATIONS" | "MST_TX_TIMEOUT_SECONDS" | "MST_AUDIT_ANCHOR_INTERVAL_MINUTES"> & {
  DEMO_MODE?: boolean;
  MST_RPC_URL?: string;
  MST_CHAIN_ID?: number;
  MST_EXPLORER_URL?: string;
  MST_CONFIRMATIONS?: number;
  MST_TX_TIMEOUT_SECONDS?: number;
  MST_AUDIT_ANCHOR_INTERVAL_MINUTES?: number;
};

export function loadConfig(environment: NodeJS.ProcessEnv = process.env): AppConfig {
  return configSchema.parse(environment);
}
