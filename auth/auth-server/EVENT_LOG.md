# Auth event history

Each Auth creates `events.jsonl` inside its configured `auth_database_dir` at startup,
for example `iotauth/auth/databases/auth101/events.jsonl`. Existing records are
preserved across restarts. Each line is a UTF-8 JSON object with UTC `timestamp`,
`authId`, `event`, `outcome`, `actor`, and `details`.

Events:
- `DELEGATION`: processed DelegationGrant requests, including rejected and failed requests.
- `ACCESS`: processed session-key requests (ordinary and delegated), including forwarding
  to another Auth and requests received from a trusted Auth. SUCCESS means authorization/key
  processing succeeded; it does not prove that the entity subsequently accessed a device.
- `REVOCATION`: processed DelegationRevoke requests, including their cascaded policy IDs,
  and successful expiration cleanup (`actor: system`, `reason: expiration`).

Outcomes are SUCCESS, REJECTED (a privilege request returned no result), or FAILED
(processing raised an exception). Logging begins after decryption identifies a registered
entity, or after a trusted Auth is recognized. Invalid wire messages rejected earlier are
still handled by the existing operational logger. Request context, nonces, and key material
are not copied to the event history. Administrative policy edits are not delegation requests.

The writer uses append mode, serializes concurrent writes, takes a file lock, and flushes
records to disk. It never truncates, rotates, or deletes the history. This is application-level
append-only logging, not protection against external file edits. Startup fails if the log
cannot be opened. A later write failure is reported to the operational logger without
changing a request outcome; database changes and event writes are not one atomic transaction.

Tests: `mvn -pl auth-server -am test` from `iotauth/auth`.
