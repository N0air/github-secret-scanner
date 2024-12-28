# GitHub Secret Scanner

A powerful Python tool designed to scan GitHub repositories for exposed secrets, credentials, and sensitive information. This tool helps security researchers and developers identify potential security risks in public repositories.

![GitHub Secret Scanner Banner](docs/banner.png)

## 🚀 Features

- **Advanced Secret Detection**: Identifies multiple types of secrets:
  - AWS Access Keys and Secrets
  - Google API Keys and OAuth tokens
  - Private Keys (RSA, SSH)
  - GitHub Tokens
  - Generic API Keys
  - Hardcoded Secrets
  - Passwords in URLs

- **Smart Scanning**:
  - Recursive repository scanning
  - Skip binary and media files
  - Real-time progress updates
  - Colored terminal output for better visibility

- **Comprehensive Results**:
  - Structured output in terminal
  - YAML report generation
  - Repository and file-level findings
  - Count of occurrences per secret type

## 📋 Prerequisites

- Python 3.7+
- GitHub Personal Access Token with `repo` scope
- Required Python packages (see `requirements.txt`)

## 🛠️ Installation

1. Clone the repository:
```bash
git clone https://github.com/N0air/github-secret-scanner.git
cd github-secret-scanner
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Set up GitHub token:
```bash
export GITHUB_TOKEN='your_github_token_here'
```

## 💻 Usage

1. Run the scanner:
```bash
python github_secret_scanner.py
```

2. Enter search details when prompted:
   - Keyword to search (e.g., company name, project name)
   - Maximum number of repositories to scan

3. View results:
   - Real-time findings in the terminal
   - Detailed report in `scan_results_TIMESTAMP.yaml`

Example usage:
```bash
$ python github_secret_scanner.py
🔍 Enter keyword: example_company
📚 Max repositories: 5

Scanning repositories...
[Results will appear here]
```

## 📊 Output Format

The tool generates two types of output:

1. **Terminal Output**:
   - Color-coded progress updates
   - Real-time findings
   - Summary of discovered secrets

2. **YAML Report**:
```yaml
- repository: "owner/repo"
  url: "https://github.com/owner/repo"
  secrets:
    - file: "path/to/file"
      matches:
        "AWS Key": 2
        "Google API Key": 1
```

## 🔍 Supported Secret Patterns

| Secret Type | Pattern Description |
|-------------|-------------------|
| AWS Key | AKIA followed by 16 characters |
| Google API Key | AIza followed by 35 characters |
| Private Key | Various private key headers |
| GitHub Token | GitHub Personal Access Token format |
| Generic API Key | Common API key patterns |
| Generic Secret | Common secret patterns |
| Password in URL | Credentials in URLs |

## 🛡️ Security Best Practices

1. **Responsible Disclosure**:
   - Report findings to repository owners
   - Follow security best practices
   - Don't exploit discovered secrets

2. **Token Security**:
   - Keep your GitHub token secure
   - Use tokens with minimal required permissions
   - Rotate tokens regularly

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

This tool is meant for security research and identifying potential security risks. Always:
- Get proper authorization before scanning repositories
- Handle any discovered secrets responsibly
- Report findings to repository owners
- Follow responsible disclosure practices

## 📞 Contact

N0air - [@N0air](https://github.com/N0air)

Project Link: [https://github.com/N0air/github-secret-scanner](https://github.com/N0air/github-secret-scanner) 