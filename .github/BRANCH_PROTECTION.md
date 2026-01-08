# Branch Protection Setup

## Overview

Branch protection prevents direct pushes to `main`, forcing all changes through pull requests where CI must pass. This is **essential for a security-critical blockchain project**.

## Why Branch Protection?

**Without protection:**
- ❌ Anyone can push broken code to main
- ❌ Tests run AFTER code is merged (too late)
- ❌ No review process
- ❌ Easy to accidentally break production

**With protection:**
- ✅ All changes go through PRs
- ✅ CI must pass before merge
- ✅ Clear audit trail
- ✅ Can't accidentally break main
- ✅ Other contributors follow same rules

## Setup Instructions

### Step 1: Navigate to Branch Protection Settings

1. Go to your GitHub repository
2. Click **Settings** (top right)
3. Click **Branches** (left sidebar)
4. Under "Branch protection rules", click **Add rule**

### Step 2: Configure Protection for `main`

**Branch name pattern:** `main`

#### Required Settings

✅ **Require a pull request before merging**
   - Require approvals: `1`
   - Dismiss stale pull request approvals when new commits are pushed: ✅
   - Require review from Code Owners: ⬜ (optional, if you set up CODEOWNERS)

✅ **Require status checks to pass before merging**
   - Require branches to be up to date before merging: ✅
   - Status checks that are required:
     - `formatting` (Code Formatting)
     - `build-test (Linux Clang 18)`
     - `build-test (Linux GCC 13)`
     - `build-test (Linux ASan+UBSan)`
     - `build-test (macOS LLVM)`
     - `fuzz-smoke` (Fuzz Smoke Test)
     - `all-checks-passed` (All Checks Passed)

   **Note:** These checks will only appear after your first PR runs. Come back and add them after first CI run.

✅ **Require conversation resolution before merging**
   - Ensures all review comments are addressed

⬜ **Require signed commits** (recommended for production)
   - Requires GPG-signed commits
   - See "Signed Commits" section below

✅ **Require linear history**
   - Prevents merge commits
   - Keeps history clean with rebase/squash

⬜ **Require deployments to succeed before merging**
   - Leave unchecked (we don't have deployments yet)

✅ **Lock branch**
   - ⬜ Leave unchecked (you need to push tags, etc.)

✅ **Do not allow bypassing the above settings**
   - ⬜ Leave unchecked initially (allow admins to bypass in emergencies)
   - ✅ Enable this in production (stricter)

✅ **Restrict who can push to matching branches**
   - ⬜ Leave empty initially (only you can push anyway)
   - Add team members here when you have collaborators

✅ **Allow force pushes**
   - ❌ **Disable** (never force push to main)

✅ **Allow deletions**
   - ❌ **Disable** (never delete main branch)

### Step 3: Save Protection Rule

Click **Create** at the bottom of the page.

## Workflow After Protection is Enabled

### Making Changes

```bash
# 1. Create feature branch
git checkout -b feature/add-new-feature

# 2. Make changes and commit
git add .
git commit -m "Add new feature"

# 3. Push branch
git push -u origin feature/add-new-feature

# 4. Open PR on GitHub
# Go to repository → "Compare & pull request" button

# 5. Wait for CI to pass (5-10 minutes)

# 6. Review your own PR (optional but recommended)

# 7. Click "Merge pull request" when CI is green

# 8. Delete feature branch
git branch -d feature/add-new-feature
git push origin --delete feature/add-new-feature
```

### Emergency: Bypass Protection

If CI is broken and you need to push a fix:

**Option 1: Temporarily disable protection**
1. Settings → Branches → Edit rule
2. Uncheck "Require status checks"
3. Push fix to main
4. Re-enable protection

**Option 2: Use admin bypass** (if available)
1. Open PR as normal
2. As admin, you can merge without waiting for checks
3. Only use in true emergencies!

## Signed Commits (Recommended for Production)

### Why Sign Commits?

- Proves commits are actually from you
- Prevents commit spoofing
- Required by some organizations

### Setup GPG Signing

#### 1. Generate GPG Key

```bash
# Install GPG
brew install gnupg  # macOS
sudo apt install gnupg  # Linux

# Generate key
gpg --full-generate-key
# Choose: RSA and RSA, 4096 bits, no expiration
# Enter your name and email (must match GitHub)
```

#### 2. Add GPG Key to GitHub

```bash
# List your keys
gpg --list-secret-keys --keyid-format=long

# Copy the key ID (after sec rsa4096/)
# Example: sec   rsa4096/ABC123DEF456 → copy ABC123DEF456

# Export public key
gpg --armor --export ABC123DEF456

# Copy output and add to GitHub:
# Settings → SSH and GPG keys → New GPG key
```

#### 3. Configure Git to Sign Commits

```bash
# Set signing key
git config --global user.signingkey ABC123DEF456

# Sign all commits by default
git config --global commit.gpgsign true

# Sign tags
git config --global tag.gpgsign true
```

#### 4. Test Signing

```bash
git commit -m "Test signed commit"
# Should sign automatically

# Verify
git log --show-signature -1
# Should show "Good signature from ..."
```

#### 5. Enable Signed Commit Requirement

Go back to Branch Protection → Enable "Require signed commits"

## CODEOWNERS File (Optional)

Automatically request reviews from code owners:

```bash
# Create .github/CODEOWNERS
cat > .github/CODEOWNERS << 'EOF'
# Default owner for everything
* @yourusername

# Specific owners for security-critical code
/src/validation/ @yourusername @securityexpert
/src/consensus/ @yourusername @securityexpert

# Network code
/src/network/ @yourusername @networkexpert

# Fuzzing
/fuzz/ @yourusername
EOF

git add .github/CODEOWNERS
git commit -m "Add CODEOWNERS file"
```

Then enable in Branch Protection:
- "Require review from Code Owners": ✅

## PR Templates (Recommended)

Create a template to guide PR descriptions:

```bash
# Create .github/pull_request_template.md
cat > .github/pull_request_template.md << 'EOF'
## Summary

<!-- Brief description of changes -->

## Type of Change

- [ ] Bug fix (non-breaking change which fixes an issue)
- [ ] New feature (non-breaking change which adds functionality)
- [ ] Breaking change (fix or feature that would cause existing functionality to not work as expected)
- [ ] Performance improvement
- [ ] Refactoring (no functional changes)
- [ ] Documentation update

## Testing

- [ ] Unit tests pass locally
- [ ] Added new tests for new functionality
- [ ] Tested with ASan/UBSan locally
- [ ] Manual testing performed

## Security Considerations

<!-- Any security implications of this change? -->

## Checklist

- [ ] Code follows project style guidelines
- [ ] Self-review of code completed
- [ ] Comments added for complex logic
- [ ] Documentation updated (if needed)
- [ ] No new compiler warnings
- [ ] All CI checks pass

## Related Issues

<!-- Link to GitHub issues: Fixes #123 -->
EOF

git add .github/pull_request_template.md
git commit -m "Add PR template"
```

## Common Issues and Solutions

### Issue: Can't push to main

```
remote: error: GH006: Protected branch update failed
To github.com:user/repo.git
 ! [remote rejected] main -> main (protected branch hook declined)
error: failed to push some refs
```

**Solution:** This is expected! Create a PR instead:
```bash
git checkout -b fix/my-fix
git push -u origin fix/my-fix
# Open PR on GitHub
```

### Issue: CI checks not showing up in branch protection

**Solution:**
1. Open a test PR first
2. Wait for CI to run
3. Then the check names will appear in branch protection settings
4. Go back and add them to required status checks

### Issue: PR says "1 approval required" but you're the only developer

**Solution:**
1. You can approve your own PR (GitHub allows this)
2. Or change setting: Branch Protection → "Require approvals" → `0`
3. Still keep status checks required!

### Issue: Can't merge because "branch is out of date"

**Solution:**
```bash
# Update your branch
git checkout feature/my-feature
git fetch origin
git rebase origin/main  # or: git merge origin/main

# Force push (safe on feature branches)
git push --force-with-lease
```

### Issue: Need to push directly in emergency

**Temporary disable:**
```bash
# 1. Settings → Branches → Edit rule for main
# 2. Uncheck all requirements temporarily
# 3. Push your fix
# 4. Re-enable all requirements
```

## Verification

After setup, verify protection is working:

```bash
# Try to push directly to main (should fail)
git checkout main
echo "test" >> README.md
git add README.md
git commit -m "Test: should be blocked"
git push origin main

# Expected error:
# remote: error: GH006: Protected branch update failed
```

If this succeeds, protection is NOT enabled correctly!

## Additional Protection (Optional)

### Require Multiple Reviewers (for teams)

Branch Protection → "Require approvals": `2`

### Restrict Who Can Dismiss Reviews

Branch Protection → "Restrict who can dismiss pull request reviews"
- Add trusted maintainers only

### Require Specific Status Checks

For critical files, require additional checks:
- Security scan must pass
- Performance benchmarks must not regress
- Documentation builds successfully

### Enable Required Deployments

If you have staging environment:
- Require successful staging deployment before allowing merge

## Summary: Recommended Settings

| Setting | Recommendation | Why |
|---------|---------------|-----|
| **Require PR** | ✅ Yes | Forces review process |
| **Require approvals** | `1` (or `0` if solo) | Review your own code |
| **Require status checks** | ✅ Yes | CI must pass |
| **Require up-to-date branch** | ✅ Yes | Prevent merge conflicts |
| **Require conversation resolution** | ✅ Yes | Address all comments |
| **Require signed commits** | ⚠️ Production only | Prevent spoofing |
| **Require linear history** | ✅ Yes | Clean git log |
| **Allow force pushes** | ❌ No | Protect history |
| **Allow deletions** | ❌ No | Protect branch |
| **Allow bypass** | ⚠️ Admin only | Emergency fixes |

## Next Steps

1. ✅ Enable branch protection with recommended settings
2. ✅ Open a test PR to verify CI runs
3. ✅ Add required status checks after first CI run
4. ✅ Create PR template (optional)
5. ✅ Set up CODEOWNERS (optional)
6. ✅ Configure GPG signing (production)

**Your main branch is now protected!** 🔒
