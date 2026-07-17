# CI Policy Examples

These policies demonstrate three CI outcomes against `examples/support-pack/context.jsonl`:

- `pass-policy.json` reports findings but exits successfully by failing only on critical issues.
- `fail-policy.json` exits with code `1` when high-severity findings are present.
- `malformed-policy.json` exits with code `2` because policy validation rejects its regex.

Run all three cases locally:

```bash
make ci-policy-demo
```
