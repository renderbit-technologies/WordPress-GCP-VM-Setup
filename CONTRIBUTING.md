# Contributing to WordPress GCP VM Setup

First off, thanks for taking the time to contribute!

The following is a set of guidelines for contributing to this repository. These are mostly guidelines, not rules. Use your best judgment, and feel free to propose changes to this document in a pull request.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [How Can I Contribute?](#how-can-i-contribute)
  - [Reporting Bugs](#reporting-bugs)
  - [Suggesting Enhancements](#suggesting-enhancements)
  - [Pull Requests](#pull-requests)
- [Styleguides](#styleguides)
  - [Shell Script Styleguide](#shell-script-styleguide)

## Code of Conduct

This project and everyone participating in it is governed by a Code of Conduct. By participating, you are expected to uphold this code. Please report unacceptable behavior to the repository maintainers.

## How Can I Contribute?

### Reporting Bugs

This section guides you through submitting a bug report.

- **Use a clear and descriptive title** for the issue to identify the problem.
- **Describe the exact steps to reproduce the problem** in as many details as possible.
- **Provide specific examples** to demonstrate the steps.
- **Include your environment details** (e.g., Ubuntu version, specific GCP machine type used).

### Suggesting Enhancements

This section guides you through submitting an enhancement suggestion, including completely new features and minor improvements to existing functionality.

- **Use a clear and descriptive title** for the issue to identify the suggestion.
- **Provide a step-by-step description of the suggested enhancement** in as many details as possible.
- **Explain why this enhancement would be useful** to most users.

### Pull Requests

The process described here has several goals:

- Maintain the quality of the project.
- Fix problems that are important to users.
- Engage the community in working toward the best possible product.

1. Fork the repo and create your branch from `main`.
2. If you've added code that should be tested, add tests.
3. Ensure the test suite passes.
4. Make sure your code lints (see Styleguides below).
5. Issue that pull request!

## Styleguides

### Shell Script Styleguide

- **Interpreter**: Ensure all scripts start with the `#!/bin/bash` shebang.
- **Indentation**: Use 2 or 4 spaces for indentation. Do not mix tabs and spaces.
- **Variables**:
  - Use UPPERCASE for exported/global variables.
  - Use lowercase for local variables.
  - Quote valid references (e.g., `"$VAR"`).
- **Functions**: Use functions to modularize code.
- **Linting**: We recommend using [ShellCheck](https://www.shellcheck.net/) to detect potential issues in your logic.
- **Comments**: Comment your code where necessary, especially for complex logic.

## Testing Changes

Since this project involves system-level changes (installing packages, modifying configs), **please test your changes on a fresh Ubuntu 24.04 LTS VM** before submitting a PR. This ensures that the scripts interact correctly with a clean environment.
