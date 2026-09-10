# FW-INTEGRITY dependency graph

```text
Customer Root / human control
        |
        v
FW-ID identity ---- FW-KEYS / FW-ROOT cryptographic authority
        |                         |
        v                         v
FW-ASOC agent authority ---- deterministic policy / Action Tickets
        |                         |
        +------------+------------+
                     v
              Model Broker ---- MCP Gateway
                     |
                     v
       canonical events / telemetry normalization
                     |
                     v
        FW-AID AI intrusion classification
          /          |              \
     FW-AV       FW-ENDPOINT      FW-HARNESS
          \          |              /
                     v
             FW-SOC incident correlation
                     |
                     v
       FW-EVID Evidence + Mission Control audit
                     |
                     v
             FW-REC recovery / rollback
                     |
                     v
                 FW-TEST
                     |
                     v
              FW-INTEGRITY gate
```

Authority ownership flows downward only after identity and deterministic policy
validation. Review, Evidence, and Integrity observe and prove the path; they do
not grant authority. FW-ASOC consumes identity, policy, model, MCP, Action
Ticket, Evidence, and kill-switch boundaries; it must not replace them.
FW-AID consumes the same canonical identity, keys, model, MCP, endpoint,
browser/email, event, policy, SOC, Evidence, recovery, and Mission Control
owners. It adds AI-specific classification and correlation, never authority.

Current checkout reality: several named families are still roadmap ownership
labels rather than concrete modules. `swarm.integrity` records those gaps
instead of treating the graph as proof of implementation.
