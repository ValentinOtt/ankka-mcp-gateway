## Summary

Describe the public contract or behavior changed and why.

## Release-boundary checklist

- [ ] `npm run check` passes.
- [ ] Tests use synthetic data only.
- [ ] No credential, private data, private hostname, provider locator, generated release, signing material, or deployment authority is included.
- [ ] New dependencies or transferred material are recorded in `ORIGINS.md` and `THIRD_PARTY_NOTICES.md` when applicable.
- [ ] Credential custody, authorization, logging, update, rollback, and removal effects are documented when applicable.
- [ ] Write-capable behavior has a separately reviewed capability, authorization, and audit design.
