# Quickstart — governance in 30 seconds

Three real GatewayStack decisions running on your machine. **No IdP, no backend,
no config.**

```bash
npm install
npm start
```

You'll see:

```
1 · Deny-by-default policy (validatabl)
  ✅ ALLOW  read_file        → Matched rule: allow-reads (allow)
  🛑 DENY   delete_database  → No rules matched; default: deny

2 · PII redaction (transformabl)
  in : Email me at john@acme.com or call about SSN 123-45-6789.
  out: Email me at [EMAIL] or call about SSN [SSN].
  detected: email, ssn

3 · Rate limit + budget guard (limitabl)
  call 1: ✅ ALLOW
  ...
  call 4: 🛑 DENY  → Rate limited. Retry after 60s
```

Everything here is pure `-core` library code — the same logic the Express
middleware wraps. See [`index.ts`](./index.ts); it's ~50 lines. To wire these as
HTTP middleware in front of your own tools/models, see the
[full-stack example](../../README.md#full-stack-example).
