# Testing GitHub Actions Locally

## Option 1: Using `act` (Docker)

[`act`](https://github.com/nektos/act) is the most popular tool for running GitHub Actions locally.

### Installation

```bash
# macOS
brew install act

# Linux (using nvm)
curl https://raw.githubusercontent.com/nektos/act/master/install.sh | sudo bash
```

### Usage

```bash
# List available workflows
act -l

# Run the CI workflow
act push

# Run a specific job
act -j build

# Use a specific event
act pull_request
```

**Note:** `act` requires Docker and does not support Podman directly.

## Option 2: Using `wrkflw` (Podman/Docker)

[`wrkflw`](https://github.com/bahdotsh/wrkflw) supports both Docker and Podman.

### Installation

```bash
# Install via cargo
cargo install wrkflw
```

### Usage

```bash
# Validate workflow
wrkflw validate .github/workflows/ci.yml

# Run workflow (with Podman)
CONTAINER_RUNTIME=podman wrkflw run .github/workflows/ci.yml
```

## Option 3: Manual Local Testing

You can also run the Stack commands directly locally to test the same build process:

```bash
# Create the CI stack.yaml override
cat > stack-ci.yaml <<EOF
resolver: lts-22.0
arch: x86_64
compiler-check: match-exact
system-ghc: false
packages:
- .
EOF

# Build
stack --stack-yaml stack-ci.yaml build --fast --test --no-run-tests

# Test
stack --stack-yaml stack-ci.yaml test --fast

# Build docs (optional)
stack --stack-yaml stack-ci.yaml haddock
```

This mimics what CI does without needing any special tools.

