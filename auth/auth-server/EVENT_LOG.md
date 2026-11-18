# Auth event history

Each Auth creates `authlog.txt` inside its configured `auth_database_dir` at startup,
for example `iotauth/auth/databases/auth101/authlog.txt`. Existing records are
preserved across restarts. Logback writes UTF-8 lines with the UTC timestamp first:

```text
[2026-11-17T21:29:11.517Z] Auth101 ACCESS SUCCESS actor="robot1" details={"group":"Item_A","numKeys":1}
```

`Z` denotes UTC. Actor and detail values use JSON escaping so embedded newlines
cannot create fake log records. Existing `events.jsonl` files are left untouched;
new events go to `authlog.txt`.

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

The writer uses a dedicated Logback logger and a non-rolling FileAppender in append
and prudent modes. Writes are locked and immediately flushed to the output stream.
This does not guarantee durability across power loss. It never truncates, rotates,
or deletes history. This is application-level append-only logging, not protection
against external edits. Startup fails if the file cannot be opened; subsequent
I/O errors are handled by Logback's status system. Database changes and log writes
are not one atomic transaction.

Build and test: `mvn -pl auth-server -am package` from `iotauth/auth`.
Restart Auth using the rebuilt JAR to activate the new format.
