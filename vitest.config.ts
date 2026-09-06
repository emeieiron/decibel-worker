import { defineConfig } from "vitest/config";
import { cloudflareTest } from "@cloudflare/vitest-plugin";

export default defineConfig({
  test: {
    projects: [
      { test: { name: "node", environment: "node", include: ["test/**/*.test.ts"] } },
      {
        plugins: [cloudflareTest({
          miniflare: {
            compatibilityDate: "2026-08-31",
            compatibilityFlags: ["nodejs_compat"],
          },
        })],
        test: { name: "workers", include: ["test/**/*.test.ts"] },
      },
    ],
  },
});
