# Release Notes (Draft)

## Unreleased

### Infrastructure & Publishing
- Added GitHub Actions repository secrets required for Docker publishing:
  - `DOCKERHUB_USERNAME`
  - `DOCKERHUB_TOKEN`
  - `DOCKERHUB_NAMESPACE`
- Docker Hub org namespace is now `phoenixsecdev` with repository `phoenixsecdev/phoenix`.
- Updated release workflow Docker image target from `phoenixsec/phoenix` to `phoenixsecdev/phoenix`.
- Added `workflow_dispatch` trigger to `release.yml` so releases can be run manually for verification.

### Repository Security
- Enabled branch protection on `main`:
  - Pull request required before merge
  - 1 required approval
  - Dismiss stale reviews on new commits
  - Require conversation resolution
  - Force-push disabled
  - Branch deletion disabled
  - Admins are enforced

### Notes
- Deploy keys are disabled by org/repo policy, so push auth was set up using a personal GitHub SSH key instead.
