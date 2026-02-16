# Autogrep

Autogrep is a tool for automatically generating and filtering Semgrep rules from vulnerability patches. It addresses a critical need in the security tooling ecosystem that emerged after Semgrep announced that their official rules are no longer available under permissive licenses. This change led to the creation of Opengrep ([opengrep/opengrep](https://github.com/opengrep/opengrep)), a community fork supported by several security vendors.

Autogrep bridges the gap by automating the creation and maintenance of high-quality security rules using Large Language Models (LLMs). Instead of relying on manual rule curation, which is time-consuming and requires constant maintenance, Autogrep automatically generates rules from known vulnerability fixes and validates them for accuracy.

The project leverages several key resources:
- [patched-codes/semgrep-rules](https://github.com/patched-codes/semgrep-rules): A collection of permissively licensed Semgrep rules used as a foundation
- [MoreFixes Dataset](https://zenodo.org/records/13983082): A comprehensive dataset of CVE fix commits from the paper "MoreFixes: A Large-Scale Dataset of CVE Fix Commits Mined through Enhanced Repository Discovery"

## Features

- Automatic rule generation from vulnerability patches
- Support for multiple programming languages
- Duplicate rule detection using embeddings
- Rule quality evaluation using LLM
- Validation against original vulnerabilities
- Filtering of project-specific and low-quality rules
- Caching system for processed patches and repositories

## Prerequisites

- Python 3.8 or higher
- Git installed and available in PATH
- Semgrep CLI installed
- An LLM API key (Anthropic by default, also supports DeepSeek and OpenAI)

## Installation

1. Clone the repository and the initial rule set:
```bash
# Clone Autogrep
git clone https://github.com/yourusername/autogrep.git
cd autogrep

# Clone initial permissively licensed rules
git clone https://github.com/patched-codes/semgrep-rules.git rules
```

2. Create and activate a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Install Semgrep CLI:
```bash
pip install semgrep
```

5. Download the MoreFixes dataset:
```bash
wget https://zenodo.org/records/13983082/files/cvedataset-patches.zip
unzip cvedataset-patches.zip -d cvedataset-patches
```

6. Set up your LLM API key (Anthropic/Claude by default):
```bash
export ANTHROPIC_API_KEY=your_api_key_here

# Or use a different provider:
# export LLM_PROVIDER=deepseek
# export DEEPSEEK_API_KEY=your_api_key_here
```

## Usage

The project consists of two main components:

1. Rule Generation (`main.py`):
```bash
python main.py --patches-dir /path/to/patches --output-dir generated_rules
```

2. Rule Filtering (`rule_filter.py`):
```bash
python rule_filter.py --input-dir generated_rules --output-dir filtered_rules
```

### Command Line Arguments

#### Main Script (main.py)
- `--patches-dir`: Directory containing vulnerability patches (default: "cvedataset-patches")
- `--output-dir`: Directory for generated rules (default: "generated_rules")
- `--repos-cache-dir`: Directory for cached repositories (default: "cache/repos")
- `--max-files-changed`: Maximum number of files changed in patch (default: 1)
- `--max-retries`: Maximum number of LLM generation attempts (default: 3)
- `--log-level`: Logging level (default: "INFO")

#### Rule Filter Script (rule_filter.py)
- `--input-dir`: Directory containing generated rules (default: "generated_rules")
- `--output-dir`: Directory for filtered rules (default: "filtered_rules")
- `--embedding-model`: Sentence-transformers model for embeddings (default: "all-MiniLM-L6-v2")
- `--log-level`: Logging level (default: "INFO")

## Project Structure

```
autogrep/
├── main.py                 # Main rule generation script
├── rule_filter.py         # Rule filtering and quality control
├── config.py             # Configuration and settings
├── llm_provider.py       # LLM provider abstraction layer
├── llm_client.py         # LLM integration for rule generation
├── patch_processor.py    # Patch file processing
├── rule_validator.py     # Rule validation logic
├── rule_manager.py       # Rule management and storage
├── git_manager.py        # Git repository handling
├── cache_manager.py      # Caching system
└── requirements.txt      # Project dependencies
```

## Output

The final filtered rules will be available in the `filtered_rules` directory, organized by programming language. These rules can be used with either Semgrep or Opengrep projects:

```
filtered_rules/
├── python/
│   └── repo_rules.yml
├── javascript/
│   └── repo_rules.yml
└── java/
    └── repo_rules.yml
```

### Using the Generated Rules

1. With Semgrep:
```bash
semgrep --config filtered_rules/python/repo_rules.yml path/to/your/code
```

2. With Opengrep:
```bash
opengrep scan --rules filtered_rules/python/repo_rules.yml path/to/your/code
```
## Articles

- [Autogrep: Automated Generation and Filtering of Semgrep Rules from Vulnerability Patches](https://lambdasec.github.io/AutoGrep-Automated-Generation-and-Filtering-of-Semgrep-Rules-from-Vulnerability-Patches/)
