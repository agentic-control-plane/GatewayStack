# Examples

Runnable GatewayStack examples.

| Example | What it shows | Setup |
|---------|---------------|-------|
| [`quickstart/`](./quickstart) | Deny-by-default policy, PII redaction, and rate limiting — three real decisions printed to your console | **None.** `npm install && npm start` |

The quickstart uses only the framework-agnostic `-core` packages, so it runs
anywhere Node runs, with zero external services. Wiring the same layers as
Express middleware (which does need an IdP for the identity layer) is covered in
the [root README](../README.md#full-stack-example).
