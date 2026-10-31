import { parseManifest, type Manifest } from "../src/config.js";

/** Builds a valid local manifest; private-network approval is explicit, as required. */
export function localManifest(origin: string, over: Record<string, unknown> = {}): Manifest {
  const host = new URL(origin).hostname;
  return parseManifest({
    version: "1",
    project: "demo",
    environment: "local",
    authorization: { acknowledged: true, owner: "navsentry-tests" },
    targets: { origins: [origin], allowed_paths: ["/**"], denied_paths: ["/admin/**"], seed_paths: ["/", "/api/profile", "/api/error", "/api/token"] },
    network: { allow_private: [{ host, approved_by: "navsentry-tests", reason: "local disposable demo app" }] },
    safety: { mode: "observe", max_requests: 100, max_requests_per_second: 20, max_duration_seconds: 60 },
    report: { language: "en", formats: ["json", "markdown", "sarif"] },
    ...over,
  });
}
