# Contributing to SD-JWT

Thank you for your interest in contributing to SD-JWT!

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/yourusername/sd-jwt.git`
3. Create a branch: `git checkout -b feature/your-feature-name`
4. Make your changes
5. Run tests: `stack test`
6. Ensure code builds: `stack build`
7. Commit your changes: `git commit -m "Add feature: description"`
8. Push to your fork: `git push origin feature/your-feature-name`
9. Create a Pull Request

## Development Setup

```bash
# Install Stack if you haven't already
# https://docs.haskellstack.org/en/stable/README/

# Build the project
stack build

# Run tests
stack test

# Build documentation
stack haddock
```

## Code Style

- Follow Haskell best practices
- Use meaningful function and variable names
- Add Haddock documentation for public functions
- Include type signatures for top-level functions

## Testing

- Add tests for new features
- Ensure all existing tests pass
- Follow the existing test structure in `test/`
- Property-based tests are encouraged for core functionality

## Pull Request Process

1. Update documentation if needed
2. Add tests for new functionality
3. Ensure all tests pass
4. Update CHANGELOG.md if applicable
5. Create a clear PR description explaining the changes

## Questions?

Feel free to open an issue for questions or discussions about contributions.

