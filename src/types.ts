export type SessionRole = "anonymous" | "owner" | "api";

export interface SessionClaims {
  exp: number;
  iat: number;
  jti: string;
  network: "testnet" | "mainnet";
  role: SessionRole;
  subaccount?: string;
  wallet?: string;
}

export interface ChallengeRecord {
  challenge: string;
  expiresAt: number;
}

export interface SponsorshipRecord {
  fingerprint: string;
  network: "testnet" | "mainnet";
  role: Exclude<SessionRole, "anonymous">;
  subaccount?: string;
  status: "pending" | "submitted";
  transactionHash?: string;
  expiresAt: number;
  wallet: string;
}

export interface Env {
  NONCES: DurableObjectNamespace;
  SESSIONS: DurableObjectNamespace;
  SPONSORSHIPS: DurableObjectNamespace;
  ANONYMOUS_RATE_LIMITER: RateLimit;
  AUTHENTICATED_RATE_LIMITER: RateLimit;
  IP_BACKSTOP_RATE_LIMITER: RateLimit;
  NETWORK: "testnet" | "mainnet";
  APP_ORIGIN: string;
  DECIBEL_ORIGIN: string;
  DECIBEL_REST_ORIGIN: string;
  DECIBEL_WS_ORIGIN: string;
  APTOS_FULLNODE_ORIGIN: string;
  GAS_STATION_ORIGIN: string;
  DECIBEL_PACKAGE_ADDRESS: string;
  USDC_METADATA_ADDRESS: string;
  DECIBEL_NODE_API_KEY: string;
  GAS_STATION_API_KEY?: string;
  SESSION_SIGNING_KEY: string;
}
