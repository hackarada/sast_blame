# SAST-Blame

A Python library for integrating Static Application Security Testing (SAST) results with version control blame information using Semgrep, GitLab, and GitHub APIs.

## Installation

```bash
pip install sast-blame
```

## Features

- Integration with Semgrep for SAST analysis
- GitLab API integration for repository and blame information
- GitHub API integration for repository and blame information
- Unified interface for working with multiple VCS providers

## Requirements

- Python 3.8 or higher
- Semgrep
- GitLab/GitHub API access tokens

## Usage

```python
from sast_blame import SastAnalyzer

# Initialize the analyzer
analyzer = SastAnalyzer(
    gitlab_token="your_gitlab_token",
    github_token="your_github_token"
)

# Run analysis
results = analyzer.analyze_repository("repository_url")
```

## Development

1. Clone the repository
2. Install development dependencies:
   ```bash
   pip install -e ".[dev]"
   ```
3. Run tests:
   ```bash
   pytest
   ```

## License

MIT License
