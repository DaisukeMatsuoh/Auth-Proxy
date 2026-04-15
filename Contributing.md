# Contributing to auth-proxy

Thank you for your interest in contributing! Any form of contribution is welcome — bug reports, feature suggestions, documentation improvements, and code changes alike.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [How to Contribute](#how-to-contribute)
- [Reporting Bugs](#reporting-bugs)
- [Suggesting Features](#suggesting-features)
- [Submitting Pull Requests](#submitting-pull-requests)
- [Commit Guidelines](#commit-guidelines)
- [Development Setup](#development-setup)
- [License](#license)

---

## Code of Conduct

Please be respectful and constructive in all interactions. This project follows a basic principle: treat others as you would like to be treated.

---

## How to Contribute

There are many ways to contribute, and you don't need to write code to make a meaningful impact:

- Report a bug you encountered
- Suggest a feature or improvement
- Improve documentation or fix a typo
- Review open pull requests
- Share the project with others who might find it useful

---

## Reporting Bugs

Before opening a new issue, please search existing issues to avoid duplicates.

When reporting a bug, include as much of the following as possible:

- A clear description of the problem
- Steps to reproduce the behavior
- Expected behavior vs. actual behavior
- Your environment (OS, Rust version, how auth-proxy is deployed)
- Relevant log output (`sudo journalctl -u auth-proxy -n 50`)

---

## Suggesting Features

Open an issue with the `enhancement` label and describe:

- What you'd like to be able to do
- Why this would be useful (your motivation or use case)
- Any alternative approaches you've considered

Feature requests don't need to be fully specified — a rough idea with a clear motivation is enough to start a conversation.

---

## Submitting Pull Requests

1. Fork the repository and create a branch from `main`.
2. Make your changes. If adding new behavior, include tests where appropriate.
3. Ensure the build and tests pass:
   ```bash
   cargo build
   cargo test
   ```
4. Open a pull request with a clear description of what changed and why.

For significant changes, consider opening an issue first to discuss the approach before investing time in implementation.

---

## Commit Guidelines

**Language:** Write commits in any language you are comfortable with. Machine translation is widely available and language should never be a barrier to contributing.

**Content:** Each commit message should make two things clear:

- **What** was changed — a concise summary of the modification
- **Why** — the motivation behind it; what problem it solves, what behavior it improves, or what prompted the change

A useful way to think about it: a future reader (or your future self) skimming the git log should be able to understand not just what happened, but why it was worth doing.

There is no enforced format. A single well-written sentence often suffices. Longer context can go in the body of the commit message if needed.

**Examples of helpful commit messages:**

```
# Concise but complete
Add 500ms delay on login failure to deter brute-force attacks

# With body for more context
Strip X-Auth-* headers from incoming requests before auth check

Without this, a client could forge X-Auth-User and bypass identity
verification on the upstream service. Headers are now removed at the
middleware layer before any handler runs.

# Fixing a specific behavior
Fix session cookie not being cleared on logout in Safari

Safari requires explicit Max-Age=0 to delete cookies; omitting it
caused sessions to persist after logout on that browser.
```

---

## Development Setup

```bash
# Clone and build
git clone https://github.com/<your-org>/auth-proxy.git
cd auth-proxy
cargo build

# Run tests
cargo test

# Run with a local .env for development
cp .env.example .env
# Edit .env as needed
cargo run -- serve
```

For cross-compilation targeting Linux from macOS:

```bash
cargo install cross --git https://github.com/cross-rs/cross

# x86_64
cross build --release --target x86_64-unknown-linux-musl

# ARM (Graviton etc.)
cross build --release --target aarch64-unknown-linux-musl
```

---

## License

By contributing to this project, you agree that your contributions will be licensed under the [MIT License](LICENSE).
