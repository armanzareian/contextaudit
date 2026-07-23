# CI Policy Examples

These files demonstrate common CI outcomes against `examples/support-pack/context.jsonl`:

- `pass-policy.json` reports findings but exits successfully by failing only on critical issues.
- `fail-policy.json` exits with code `1` when high-severity findings are present.
- `malformed-policy.json` exits with code `2` because policy validation rejects its regex.
- `suppressions.json` accepts the high-severity synthetic fixture fingerprints so a strict policy
  can keep reporting lower-severity findings without failing the job.

Run the cases locally:

```bash
make ci-policy-demo
make suppression-demo
```
