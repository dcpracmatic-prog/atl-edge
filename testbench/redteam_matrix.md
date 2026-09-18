# ATL Hardened Red-Team v1 — Results Matrix

Started: `2026-09-18T22:02:08Z`  
Finished: `2026-09-18T22:02:08Z`

| Attack | Effect | Package | Data exposed | External | Status | Notes |
|--------|:------:|:-------:|:------------:|----------|--------|-------|
| RT0 Legitimate baseline (control) | YES | YES | YES | SUCCESS | **PASS** | baseline |
| RT1 Direct DataPlane issue without gate | NO | YES | YES | SUCCESS | **BYPASS** | direct-dataplane-issue |
| RT2 Denied tool/operation via MVP | NO | NO | NO | INERT | **BLOCK** | morph-or-policy |
| RT3 Mutation after conceptual gate | NO | NO | NO | INERT | **BLOCK** | mutation-blocked |
| RT4 Field escalation to SSN | NO | NO | NO | INERT | **BLOCK** | data-auth |
| RT5 Unauthorized resource | NO | NO | NO | INERT | **BLOCK** | data-auth |
| RT6 Missing license entitlement | NO | NO | NO | INERT | **BLOCK** | license |
| RT7 Wrong license capability | NO | NO | NO | INERT | **BLOCK** | construct-denied |
| RT8 License node mismatch | NO | NO | NO | INERT | **BLOCK** | construct-denied |
| RT9 Duplicate request_id | NO | NO | NO | INERT | **BLOCK** | dup |
| RT10 Concurrent same request_id (16 workers) | NO | NO | NO | INERT | **BLOCK** | successes=1 |
| RT11 ATLP open with wrong node key | NO | NO | NO | INERT | **BLOCK** | atlp-node |
| RT12 ATLP replay second open | NO | NO | NO | INERT | **BLOCK** | replay-blocked |
| RT13 Fault: non-dict proposal | NO | NO | NO | INERT | **BLOCK** | fault |
| RT14 Composition: MORPH fail / data would pass | NO | NO | NO | INERT | **BLOCK** | comp |
| RT15 Composition: data fail / license ok | NO | NO | NO | INERT | **BLOCK** | comp |
| RT16 Edge API: no HTTP raw issue_for_agent / data_plane | NO | NO | NO | INERT | **BLOCK** | harness-exception |
| RT17 Lying Content-Length DoS on Edge API | NO | NO | NO | INERT | **BLOCK** | harness-exception |
| RT18 Slow-drip body vs absolute read deadline | NO | NO | NO | INERT | **BLOCK** | slow-drip-deadline |
| RT19 Egress tool sweep (premium/http/openai/shell/...) | NO | NO | NO | INERT | **BLOCK** | egress-tools-all-rejected:17 |
| RT20 Outbound client on the sealing path | NO | NO | NO | INERT | **BLOCK** | no-egress-client:8files/32modules |

## Summary

- Total: 21
- BLOCK: 19
- BYPASS: 1 (known process-trust: 1, unknown: 0)
- Oracle distinct signatures (excl. control): 6
- Control baseline OK: True
- Clean (no unknown bypass): True

## Oracle classes

- `2a57a46daef7` → RT2, RT3, RT4, RT5, RT6, RT7, RT8, RT9, RT10, RT13, RT14, RT15
- `1c56af19bb72` → RT11, RT12
- `d511817c6599` → RT16, RT17
- `50f4de30c92d` → RT19, RT20
- `82a09b27dbad` → RT1
- `8a1448713563` → RT18

## Interpretation

- **RT1** documents *in-process* trust: code holding `LocalDataPlane` can seal.
- **RT16** closes the **API/network** boundary: `src/edge_api_server.py` exposes only
  `/health`, `/v1/capabilities`, `/v1/execute` over MVP. Probes for raw
  `issue_for_agent` / `data_plane` return INERT. Deploy untrusted agents as
  separate processes that only speak the Edge API.
- Other attacks must remain **BLOCK** with external code **INERT**.
