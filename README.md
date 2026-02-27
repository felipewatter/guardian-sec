
# 🔐 guardian-sec

Advanced Repository Security Posture Engine  
Holistic DevSecOps Scanner for Git Repositories

---

## 📌 Overview

guardian-sec is a security posture engine designed to perform a comprehensive audit of Git repositories, focusing on:

- Secret exposure detection
- Dependency hygiene analysis
- GitHub security configuration checks
- CI/CD security validation
- Commit history scanning
- SBOM generation (CycloneDX-ready)
- Security scoring (0–100)
- Plugin-based extensibility
- SARIF export for GitHub Security tab

Built following modern DevSecOps, Secure SDLC and OpenSSF best practices.

---

## 🎯 Problem Statement

Modern repositories frequently suffer from:

- Accidental credential leaks
- Disabled security alerts
- Unprotected branches
- Weak CI/CD controls
- Poor dependency hygiene
- Lack of SBOM transparency
- Secrets removed from HEAD but present in Git history

guardian-sec provides a unified and extensible engine to detect these issues early.

---

## 🏗 Architecture

guardian-sec/
│
├── src/
│   ├── cli.ts
│   ├── scanner.ts
│   ├── checks/
│   ├── reporters/
│   └── core/
│
├── .github/workflows/
├── SECURITY.md
├── LICENSE
└── README.md

Core Components:

- Scan Engine
- Score Engine
- Plugin Manager
- Reporters (Console, JSON, Markdown, HTML, SARIF)

---

## 🔐 Security Score Model

| Category              | Weight |
|-----------------------|--------|
| Secrets               | 25     |
| Dependencies          | 20     |
| CI/CD                 | 15     |
| Branch Protection     | 15     |
| Commit History        | 15     |
| GitHub Security       | 10     |

Score range: 0–100

---

## 🚀 Installation

Global:

npm install -g guardian-sec

Using npx:

npx guardian-sec scan .

---

## 📊 Usage

Scan repository:

guardian-sec scan .

Export Markdown:

guardian-sec scan . --format md

Generate SARIF:

guardian-sec scan . --format sarif

Generate SBOM:

guardian-sec sbom

---

## 🔍 What Is Checked?

1. Secret Detection (AWS keys, private keys, API tokens)
2. Dependency Hygiene
3. CI/CD Security Validation
4. GitHub Security Configuration
5. Commit History Secret Detection

---

## 🧩 Plugin System

Example plugin:

export default {
  name: "custom-check",
  async run(repoPath) {
    return {
      check: "Custom Policy Validation",
      passed: true,
      findings: 0
    };
  }
};

---

## 📄 SBOM Support

CycloneDX-compatible SBOM generation for supply chain transparency.

---

## 🔗 GitHub API Integration

Supports:

- Dependabot verification
- Branch protection validation
- Security alerts validation
- Repository metadata checks

---

## 🔐 Responsible Disclosure

Security vulnerabilities should NOT be reported via public issues.

Please report responsibly via private channel.

---

## 🤝 Contributing

1. Fork repository
2. Create feature branch
3. Add tests
4. Submit PR
5. Follow conventional commits

---

## 📊 Roadmap

- Web dashboard
- Slack integration
- OpenSSF Scorecard API integration
- Fuzz testing
- Multi-repository comparison

---

## 📜 License

MIT License © Felipe Watter

---

guardian-sec represents DevSecOps maturity, supply chain awareness, and enterprise-ready security architecture.
