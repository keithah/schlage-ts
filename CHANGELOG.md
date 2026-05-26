# Changelog

## 0.1.1 - 2026-05-25

- Redact embedded user records from lock status responses so account emails are not exposed through `status`.
- Expand live verification to cover settings write/restore and access-code add/update/delete.
- Add an opt-in live temporary schedule write/delete probe with `SCHLAGE_S07_VERIFY_SCHEDULES=1`.
- Add GitHub Actions CI for build, typecheck, lint, tests, and package dry-run.
- Add a scheduled issue-only watcher for new `pyschlage` releases.

## 0.1.0 - 2026-05-25

- Initial public npm release.
