# Contributing to ShadowScan

Thank you for your interest in contributing to **ShadowScan**! This document provides guidelines and instructions for contributing to this project.

## 📋 Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [How to Contribute](#how-to-contribute)
- [Development Setup](#development-setup)
- [Coding Standards](#coding-standards)
- [Submitting Changes](#submitting-changes)
- [Reporting Issues](#reporting-issues)

---

## Code of Conduct

By participating in this project, you agree to maintain a respectful and inclusive environment. We expect all contributors to:

- Be respectful and considerate in all interactions
- Welcome newcomers and help them get started
- Focus on constructive criticism and feedback
- Accept responsibility for mistakes and learn from them
- Prioritize the well-being of the community

---

## Getting Started

### Prerequisites

- Python 3.8 or higher
- Git
- A GitHub account
- Basic knowledge of networking and port scanning concepts

### Fork and Clone

1. Fork the repository on GitHub
2. Clone your fork locally:
   ```bash
   git clone https://github.com/YOUR_USERNAME/ShadowScan.git
   cd ShadowScan
   ```
3. Add the original repository as an upstream remote:
   ```bash
   git remote add upstream https://github.com/mharasiam/ShadowScan.git
   ```

---

## How to Contribute

### Types of Contributions

We welcome various types of contributions:

- **Bug Fixes**: Fix issues and errors in the code
- **New Features**: Add new scanning capabilities or features
- **Documentation**: Improve or expand documentation
- **Testing**: Add unit tests and improve test coverage
- **Code Quality**: Refactor code for better performance or readability

### Areas for Contribution

- Additional port service database entries
- New scanning techniques (UDP, SYN, FIN, etc.)
- Enhanced banner grabbing capabilities
- Export formats (CSV, XML, HTML)
- GUI interface
- Network discovery features
- OS detection capabilities

---

## Development Setup

### Install Dependencies

```bash
# Create virtual environment
python -m venv venv

# Activate virtual environment
# On Windows:
venv\Scripts\activate
# On Linux/macOS:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Install development dependencies
pip install pytest black flake8
```

### Run Tests

```bash
# Run unit tests
pytest tests/

# Run with coverage
pytest --cov=shadowscan tests/
```

### Code Formatting

```bash
# Format code with Black
black shadowscan.py

# Check code style with Flake8
flake8 shadowscan.py
```

---

## Coding Standards

### Python Style Guide

- Follow PEP 8 style guidelines
- Use meaningful variable and function names
- Add docstrings to all functions and classes
- Keep functions focused and concise
- Maximum line length: 88 characters (Black default)

### Code Structure

```python
def function_name(parameter1, parameter2):
    """
    Brief description of what the function does.
    
    Args:
        parameter1: Description of parameter1
        parameter2: Description of parameter2
    
    Returns:
        Description of return value
    
    Raises:
        ExceptionType: When this exception is raised
    """
    # Implementation
    pass
```

### Commit Messages

Use clear and descriptive commit messages:

- Use the present tense ("Add feature" not "Added feature")
- Use the imperative mood ("Move cursor to..." not "Moves cursor to...")
- Limit the first line to 72 characters or less
- Reference issues and pull requests liberally

Example:
```
Add UDP scanning capability

- Implement UDP port scanning
- Add timeout configuration for UDP
- Update documentation with UDP examples

Closes #42
```

---

## Submitting Changes

### Pull Request Process

1. Create a feature branch:
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. Make your changes and commit them:
   ```bash
   git add .
   git commit -m "Your commit message"
   ```

3. Push to your fork:
   ```bash
   git push origin feature/your-feature-name
   ```

4. Open a Pull Request on GitHub

5. Fill in the Pull Request template:
   - Description of changes
   - Related issues
   - Testing performed
   - Screenshots (if applicable)

### Pull Request Guidelines

- Keep PRs focused on a single feature or fix
- Include tests for new functionality
- Update documentation as needed
- Ensure all tests pass before submitting
- Link related issues in the PR description

---

## Reporting Issues

### Bug Reports

When reporting bugs, please include:

1. **Description**: Clear description of the bug
2. **Steps to Reproduce**: How to reproduce the issue
3. **Expected Behavior**: What you expected to happen
4. **Actual Behavior**: What actually happened
5. **Environment**: OS, Python version, ShadowScan version
6. **Screenshots**: If applicable

### Feature Requests

For feature requests, please include:

1. **Problem Statement**: What problem does this solve?
2. **Proposed Solution**: How would you like it to work?
3. **Alternatives**: Any alternative solutions considered?
4. **Additional Context**: Any other relevant information

---

## Questions?

If you have questions about contributing, feel free to:

- Open an issue with the "question" label
- Reach out to the author: Mahara HOSEN SIAM

---

Thank you for contributing to ShadowScan! Your efforts help make this tool better for the entire cybersecurity community.

---

*Made with ❤️ by Mahara HOSEN SIAM*
