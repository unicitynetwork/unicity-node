## Summary

<!-- Describe what this PR does and why. Link to any relevant issues. -->

Fixes #<!-- issue number, if applicable -->

## Type of Change

<!-- Check all that apply -->

- [ ] Bug fix (non-breaking change that fixes an issue)
- [ ] New feature (non-breaking change that adds functionality)
- [ ] Breaking change (fix or feature that would cause existing behavior to change)
- [ ] CI / tooling improvement
- [ ] Documentation update
- [ ] Refactor (no functional change)
- [ ] Performance improvement

## Changes Made

<!-- List the key changes in this PR -->

-
-
-

## Testing

<!-- Describe the tests you ran and how to reproduce them -->

- [ ] Unit tests pass locally: `./build/bin/unicity_tests -d yes "~[real]" "~[rpc]" "~[slow]"`
- [ ] Functional tests pass locally: `cd test/functional && python3 test_runner.py`
- [ ] New tests added for new behavior (if applicable)
- [ ] Tested with AddressSanitizer: `cmake -DSANITIZER=address ...`

## Consensus Impact

<!-- Does this change affect consensus rules? -->

- [ ] This PR does NOT affect consensus rules
- [ ] This PR DOES affect consensus rules (requires two maintainer reviews)

If consensus-affecting, describe the change and any backward-compatibility considerations:

## Checklist

- [ ] Code follows the project style (`clang-format` applied)
- [ ] `clang-tidy` warnings addressed
- [ ] Self-reviewed the diff for unintended changes
- [ ] Updated relevant documentation (README, ARCHITECTURE.md, etc.)
- [ ] Commit messages follow Conventional Commits format
