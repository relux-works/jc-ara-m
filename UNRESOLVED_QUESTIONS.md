# Unresolved questions

## CARD#5 production capacity

What installed active-rule capacity and worst-case metadata transaction are
physically validated on CARD#5 for the multi-rule release?

- The architecture provides persistent-memory plus applet-owned and
  caller-owned transaction commit-size formulas.
- Exact available EEPROM, allocator overhead, and transaction-buffer overhead
  are card-specific and have not been measured.
- This is a release/physical-acceptance gate, not an unresolved storage-model
  decision. Implementation remains parameterized by installed capacity.
- Resolution evidence must include the selected capacity, CAP identity,
  toolchain manifest, worst-case add/update/delete-all results in both
  transaction-ownership paths, and no card secrets.

See
[`docs/architecture/multi-rule-seac-architecture.md`](docs/architecture/multi-rule-seac-architecture.md),
sections 3.3, 8.2, and 11.

## Canary and rollback physical evidence

Have the signed alternate-AID canary and v0.1.1 rollback artifact been exercised
on a sacrificial card or CARD#5 under the WP4 maintenance protocol?

- WP3 provides deterministic asset construction, digest/signature/toolchain
  verification, a fail-closed canary-evidence schema, guarded standard-AID
  replacement, and automatic rollback ordering.
- Every canary-evidence check is false in the generated template. The migration
  command refuses execution until the pinned canary digest, selected capacity,
  rollback install/restore, mutation/read/refresh/interruption paths, both
  transaction-ownership paths, and raw-STORE denial are all recorded true.
- This remains a physical WP4 gate. WP3 performs no CARD#5 mutation and does not
  convert a host dry-run into hardware evidence.
