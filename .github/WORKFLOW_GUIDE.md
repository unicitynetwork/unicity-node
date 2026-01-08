# Daily Development Workflow

Quick reference for working with branch protection enabled.

## TL;DR

```bash
# Never push directly to main!
git checkout -b feature/my-feature
# ... make changes ...
git push -u origin feature/my-feature
# Open PR on GitHub → Wait for CI → Merge
```

## Standard Workflow

### 1. Start New Feature

```bash
# Update main
git checkout main
git pull origin main

# Create feature branch
git checkout -b feature/add-new-thing
# or: git checkout -b fix/bug-name
# or: git checkout -b refactor/cleanup-code
```

**Branch naming convention:**
- `feature/description` - New features
- `fix/description` - Bug fixes
- `refactor/description` - Code cleanup
- `docs/description` - Documentation
- `test/description` - Test additions

### 2. Make Changes

```bash
# Edit files
vim src/something.cpp

# Build and test locally
cmake --build build -j
./build/unicity_tests

# Optional: Run with sanitizers
cmake -B build-asan -DSANITIZE=address
cmake --build build-asan -j
./build-asan/unicity_tests
```

### 3. Commit Changes

```bash
# Stage files
git add src/something.cpp include/something.hpp

# Commit with descriptive message
git commit -m "Add support for X

- Implement feature Y
- Fix edge case Z
- Add tests for ABC"
```

**Good commit messages:**
- Start with verb: "Add", "Fix", "Refactor", "Update"
- First line < 72 chars (summary)
- Blank line, then detailed explanation
- Reference issues: "Fixes #123"

### 4. Push Branch

```bash
# First push
git push -u origin feature/add-new-thing

# Subsequent pushes
git push
```

### 5. Open Pull Request

**On GitHub:**
1. Go to repository
2. Click **"Compare & pull request"** (appears after push)
3. Fill in PR description:
   - What changed
   - Why it changed
   - How to test
4. Click **"Create pull request"**

**Or via CLI:**
```bash
# If you have gh CLI installed
gh pr create --title "Add feature X" --body "Description here"
```

### 6. Wait for CI

CI runs automatically (~5-10 minutes):
- ✅ Code formatting
- ✅ Linux Clang build + tests
- ✅ Linux GCC build + tests
- ✅ macOS LLVM build + tests
- ✅ AddressSanitizer build + tests
- ✅ Fuzz smoke tests

**While waiting:**
- Review your own code
- Add comments for complex logic
- Check the "Files changed" tab

### 7. Address CI Failures (if any)

**If CI fails:**

```bash
# See what failed on GitHub Actions tab

# Fix the issue locally
vim src/something.cpp

# Commit fix
git add src/something.cpp
git commit -m "Fix issue found by CI"

# Push again (CI re-runs automatically)
git push
```

**Common failures:**
- **Formatting:** Run `clang-format -i src/**/*.cpp`
- **Build error:** Check compiler version, fix syntax
- **Test failure:** Fix bug, add missing test
- **ASan error:** Fix memory leak/use-after-free

### 8. Merge PR

Once CI is green:

**Option A: Merge on GitHub**
1. Click **"Merge pull request"**
2. Choose merge strategy:
   - **"Squash and merge"** ← Recommended (clean history)
   - "Create a merge commit" (preserves commits)
   - "Rebase and merge" (linear history, keeps commits)
3. Confirm merge
4. Delete branch (click "Delete branch")

**Option B: Merge via CLI**
```bash
gh pr merge --squash --delete-branch
```

### 9. Update Local Main

```bash
# Switch to main
git checkout main

# Pull merged changes
git pull origin main

# Delete local feature branch
git branch -d feature/add-new-thing
```

## Advanced Workflows

### Updating PR with Main Branch Changes

If main advances while your PR is open:

```bash
# Option 1: Rebase (cleaner, recommended)
git checkout feature/my-feature
git fetch origin
git rebase origin/main

# Resolve conflicts if any
# ... edit files ...
git add resolved-file.cpp
git rebase --continue

# Force push (safe on feature branches)
git push --force-with-lease

# Option 2: Merge (simpler, but creates merge commit)
git merge origin/main
git push
```

### Splitting Large Changes

If PR is too big:

```bash
# Create multiple smaller PRs
git checkout -b feature/part-1
# ... add some changes ...
git push -u origin feature/part-1
# Open PR #1

# Create next part (branch from part-1)
git checkout -b feature/part-2
# ... add more changes ...
git push -u origin feature/part-2
# Open PR #2 (mark as "depends on #1")
```

### Fixing Commits Before Push

```bash
# Amend last commit
git add forgotten-file.cpp
git commit --amend --no-edit

# Interactive rebase to fix older commits
git rebase -i HEAD~3  # Edit last 3 commits
# Change "pick" to "edit" or "squash"
# Save and follow instructions

# Force push if already pushed
git push --force-with-lease
```

### Cherry-picking Fixes

```bash
# Pick a commit from another branch
git checkout main
git checkout -b hotfix/critical-bug
git cherry-pick abc123def  # commit hash from feature branch
git push -u origin hotfix/critical-bug
# Open PR
```

## Quick Commands

### Status Check
```bash
git status                    # What's changed
git branch                    # Which branch am I on?
git log --oneline -5          # Recent commits
git diff                      # Unstaged changes
git diff --staged             # Staged changes
```

### Undo Operations
```bash
git checkout -- file.cpp      # Discard changes to file
git reset HEAD file.cpp       # Unstage file
git reset --soft HEAD~1       # Undo last commit (keep changes)
git reset --hard HEAD~1       # Undo last commit (discard changes)
git clean -fd                 # Remove untracked files
```

### Remote Management
```bash
git remote -v                 # Show remotes
git fetch origin              # Download changes (don't merge)
git pull origin main          # Fetch + merge
git push origin :old-branch   # Delete remote branch
```

## Troubleshooting

### "Protected branch update failed"

**Cause:** Tried to push directly to main.

**Fix:** Create a branch instead:
```bash
git checkout -b fix/my-fix
git push -u origin fix/my-fix
```

### "Merge conflicts"

**Fix conflicts:**
```bash
git status  # See conflicted files
vim conflicted-file.cpp  # Edit conflicts (search for <<<<<<<)
git add conflicted-file.cpp
git rebase --continue  # or git merge --continue
git push --force-with-lease
```

### "CI stuck/taking too long"

Check if:
- CMake cache issue → Delete `build/` and rebuild
- macOS runner unavailable → Wait (they're slower)
- Fuzz test hanging → Check fuzz target code

**Cancel and restart:**
- Go to Actions tab → Cancel workflow → Push again

### "Can't delete branch"

```bash
# Branch not fully merged
git branch -D feature/my-branch  # Force delete

# Remote branch
git push origin --delete feature/my-branch
```

## Best Practices

### DO ✅
- Create small, focused PRs (< 500 lines)
- Write descriptive commit messages
- Test locally before pushing
- Review your own PRs
- Run formatters before committing
- Keep branches up to date with main
- Delete branches after merge

### DON'T ❌
- Push directly to main
- Create PRs with unrelated changes
- Push untested code
- Force push to main
- Leave stale branches hanging
- Commit merge conflicts
- Skip local testing

## Time-Saving Tips

### Aliases

Add to `~/.gitconfig`:
```ini
[alias]
    co = checkout
    br = branch
    ci = commit
    st = status
    unstage = reset HEAD --
    last = log -1 HEAD
    visual = log --oneline --graph --decorate --all
    amend = commit --amend --no-edit
    please = push --force-with-lease
    pr = !gh pr create
```

Usage:
```bash
git co -b feature/new      # Instead of git checkout -b
git st                     # Instead of git status
git please                 # Instead of git push --force-with-lease
```

### Pre-commit Hook

Create `.git/hooks/pre-commit`:
```bash
#!/bin/bash
# Run clang-format on staged C++ files
git diff --cached --name-only --diff-filter=ACM | \
  grep -E '\.(cpp|hpp)$' | \
  xargs -I {} clang-format -i {}

# Re-add formatted files
git diff --cached --name-only --diff-filter=ACM | \
  grep -E '\.(cpp|hpp)$' | \
  xargs git add
```

Make executable:
```bash
chmod +x .git/hooks/pre-commit
```

### VS Code Tasks

Create `.vscode/tasks.json`:
```json
{
  "version": "2.0.0",
  "tasks": [
    {
      "label": "Build and Test",
      "type": "shell",
      "command": "cmake --build build -j && ./build/unicity_tests",
      "group": {
        "kind": "test",
        "isDefault": true
      }
    }
  ]
}
```

Run with: `Cmd+Shift+P` → "Run Test Task"

## Summary

**Every day:**
1. `git checkout -b feature/name`
2. Make changes + test locally
3. `git commit -m "Description"`
4. `git push -u origin feature/name`
5. Open PR on GitHub
6. Wait for CI (☕)
7. Merge when green ✅
8. `git checkout main && git pull`

**Never:**
- ❌ `git push origin main`
- ❌ Skip local testing
- ❌ Force push to main

**Your workflow is now protected and auditable!** 🚀
