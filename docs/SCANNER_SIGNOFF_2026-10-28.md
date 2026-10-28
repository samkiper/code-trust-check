# Scanner sign-off evidence, October 28, 2026

Scope: supported static security signals, selected direct Python cross-file credential flows and limited behavior-versus-intent review. No safety certification, complete application analysis or complete requirements verification. Site owner-private; purchases paused.

| Gate | Status | Evidence / remaining work |
| --- | --- | --- |
| Shell and deserializer fixes | Completed for selected paths | Deployed scanner51/52/55 paired customer results, correct per-scan usage. SafeLoader false positive corrected and unsafe loader preserved. |
| Fixed echo severity | Completed for selected paths | Scanner56 deployed fixed argv echo medium versus Python -c untrusted input high; both engines complete; one allowance each. |
| Accuracy and intent evaluation | Partially verified | 28 authored product cases passed; five external Bandit fixtures inspected without execution, exposed and drove fixes. No representative accuracy percentage. Metadata path confidence correction pending deployment; heuristic intent limitations remain explicit. |
| Repository ingestion regression | Completed for public path | Scanner56 actual customer psf/requests scan: useful partial36/51, unsupported/empty files disclosed, one total and one repository allowance. Private fixture reconnection/current-path evidence separate. |
| Customer isolation | Partially verified | Live RLS/grants inspected; rolled-back live DB nonowner read/trash denial, recipient read and revoke passed. Two-customer browser/HTTP check pending. |
| Unexpected behavior failures | Partially verified | Scanner55 fails closed; injected local component exceptions no clean report. Worker generic502 and settlement source/local tests; deployed unexpected-failure accounting pending. Historical deployed memory/timeout accounting retained. |
| Final sign-off | Open | Resolve confirmed defects, verify affected deployed paths and close remaining isolation/accounting checks. |

Current confirmed runtime scanner56 commit69d6c75e1e362271b749fbbaaac4ac154ea6c9c0. Reported findings in third-party repositories are review signals, not confirmed vulnerabilities. Requests repository metadata-path report demonstrated why caller parameters must not be asserted to be attacker controlled without evidence.

Temporary marked Serious accounts remain non-admin throughout active testing. Preserve usage and check Stripe before eventual guarded restoration to Free. No new charges or purchases authorized. Full launch readiness remains a separate checklist.
