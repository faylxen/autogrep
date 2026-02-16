from typing import Optional, Tuple
from config import Config
from llm_provider import LLMProvider
import logging
import yaml
from patch_processor import PatchInfo
import re
from pathlib import Path

class LLMClient:
    def __init__(self, config: Config):
        self.config = config
        self.llm = LLMProvider(
            provider=config.llm_provider,
            api_key=config.llm_api_key,
            model=config.llm_model,
            base_url=config.llm_base_url,
        )
        
    def extract_response(self, text: str) -> str:
        """Remove thinking tags and markdown formatting from LLM response."""
        # Remove thinking tags
        text = re.sub(r'<think>.*?</think>', '', text, flags=re.DOTALL)
        # Remove markdown code block markers
        text = re.sub(r'^```yaml\s*', '', text, flags=re.MULTILINE)
        text = re.sub(r'^```\s*$', '', text, flags=re.MULTILINE)
        # Remove any leading/trailing whitespace
        return text.strip()
    
    def clean_yaml_text(self, text: str) -> Optional[str]:
        """Clean and validate YAML text with better error handling."""
        if not text:
            return None
            
        # Remove any YAML document markers
        text = re.sub(r'^---\s*$', '', text, flags=re.MULTILINE)
        text = re.sub(r'^\.{3}\s*$', '', text, flags=re.MULTILINE)
        
        try:
            # First try to parse the YAML
            data = yaml.safe_load(text)
            
            # Ensure we have a valid rules structure
            if not isinstance(data, dict):
                data = {'rules': [data] if data else []}
            elif 'rules' not in data:
                data = {'rules': [data]}
                
            # Clean dump with proper formatting
            return yaml.dump(data, sort_keys=False, default_flow_style=False)
        except yaml.YAMLError as e:
            logging.error(f"YAML parsing error: {e}")
            # Try to salvage malformed YAML by wrapping in rules structure
            try:
                wrapped_text = f"rules:\n  - {text}"
                data = yaml.safe_load(wrapped_text)
                return yaml.dump(data, sort_keys=False, default_flow_style=False)
            except yaml.YAMLError:
                return None

    def validate_rule_schema(self, rule: dict) -> Tuple[bool, Optional[str]]:
        """Validate that the rule has all required fields."""
        required_fields = ['id', 'pattern', 'message', 'severity', 'languages']
        
        if not isinstance(rule, dict):
            return False, "Rule must be a dictionary"
            
        missing_fields = [field for field in required_fields if field not in rule]
        if missing_fields:
            return False, f"Missing required fields: {', '.join(missing_fields)}"
            
        # Validate severity
        valid_severities = ['ERROR', 'WARNING', 'INFO']
        if rule['severity'] not in valid_severities:
            return False, f"Invalid severity level. Must be one of: {', '.join(valid_severities)}"
            
        # Ensure id is properly formatted
        if not re.match(r'^[a-z0-9-]+$', rule['id']):
            return False, "Invalid id format. Must contain only lowercase letters, numbers, and hyphens"
            
        return True, None

    def _sanitize_rule(self, rule: dict, patch_info: PatchInfo) -> dict:
        """Ensure rule has all required fields and correct format."""
        if not isinstance(rule, dict):
            rule = {'rules': [rule]}
        
        # Extract the actual rule if wrapped in 'rules' list
        if 'rules' in rule and isinstance(rule['rules'], list):
            rule = rule['rules'][0]
        
        # Ensure rule has an ID
        if 'id' not in rule:
            # Generate an ID based on the repository and commit
            commit_short = patch_info.commit_id[:8]
            rule['id'] = f"vuln-{patch_info.repo_name.lower()}-{commit_short}"
        
        # Ensure rule has languages field
        if 'languages' not in rule:
            rule['languages'] = [patch_info.file_changes[0].language]
        
        # Ensure rule has severity
        if 'severity' not in rule:
            rule['severity'] = 'ERROR'
        
        # Ensure rule has metadata
        if 'metadata' not in rule:
            rule['metadata'] = {}
        
        metadata = rule['metadata']
        if 'source-url' not in metadata:
            metadata['source-url'] = f"github.com/{patch_info.repo_owner}/{patch_info.repo_name}/commit/{patch_info.commit_id}"
        
        if 'category' not in metadata:
            metadata['category'] = 'security'
        
        if 'technology' not in metadata:
            metadata['technology'] = [patch_info.file_changes[0].language]
        
        return rule

    def generate_rule(self, patch_info: PatchInfo, error_feedback: Optional[str] = None) -> Optional[dict]:
        """Generate a Semgrep rule using the LLM with improved validation."""
        prompt = self._build_prompt(patch_info, error_feedback)
        
        try:
            system_prompt = """You generate Semgrep rules in YAML format.
    Return only the raw YAML content without any markdown formatting or additional text.
    Always include these required fields: id, pattern, message, severity, languages"""

            content = self.llm.chat_completion(
                system=system_prompt,
                user=prompt,
                temperature=0.6,
            )

            if not content:
                logging.error("No response generated from LLM")
                return None
                
            rule_text = self.extract_response(content)
            if not rule_text:
                logging.error("No valid content after extracting response")
                return None
                
            rule_text = self.clean_yaml_text(rule_text)
            if not rule_text:
                logging.error("Failed to clean YAML text")
                return None
            
            try:
                rule_data = yaml.safe_load(rule_text)
                rule = self._sanitize_rule(rule_data, patch_info)
                
                # Validate the rule schema
                is_valid, error = self.validate_rule_schema(rule)
                if not is_valid:
                    logging.error(f"Invalid rule schema: {error}")
                    return None
                
                return rule
                
            except yaml.YAMLError as e:
                logging.error(f"Error parsing generated rule YAML: {e}")
                return None
                
        except Exception as e:
            logging.error(f"Error generating rule: {e}")
            return None
        
    def _build_prompt(self, patch_info: PatchInfo, error_feedback: Optional[str] = None) -> str:
        """Build an enhanced prompt for rule generation with examples and detailed guidance."""
        # Combine all file changes with context
        all_changes = []
        for file_change in patch_info.file_changes:
            file_header = f"File: {file_change.file_path}\n"
            all_changes.append(file_header + file_change.changes)
        
        combined_changes = "\n\n".join(all_changes)
        
        language = patch_info.file_changes[0].language
        commit_short = patch_info.commit_id[:8]
        suggested_id = f"vuln-{patch_info.repo_name.lower()}-{commit_short}"
        
        # Language-specific example rules
        EXAMPLE_RULES = {
            "python": '''
    rules:
    - id: "unsafe-deserialization"
        pattern: pickle.loads($DATA)
        pattern-not: pickle.loads(trusted_data)
        pattern-inside: |
            def $FUNC(...):
                ...
        languages: ["python"]
        message: "Detected unsafe deserialization using pickle.loads(). This can lead to remote code execution."
        severity: ERROR
        metadata:
            category: security
            cwe: CWE-502
            owasp: A8:2017-Insecure Deserialization
            references:
                - https://docs.python.org/3/library/pickle.html#pickle.loads

    - id: "sql-injection"
        patterns:
            - pattern: execute($QUERY)
            - pattern-not: execute("SELECT ...")
            - pattern-not: execute(sanitized_query)
        languages: ["python"]
        message: "Potential SQL injection detected. Use parameterized queries instead."
        severity: ERROR
        metadata:
            category: security
            cwe: CWE-89
    ''',
            "javascript": '''
    rules:
    - id: "xss-innerHTML"
        pattern: $ELEMENT.innerHTML = $DATA
        pattern-not-inside: |
            $ELEMENT.innerHTML = DOMPurify.sanitize($DATA)
        languages: ["javascript"]
        message: "Potential XSS vulnerability using innerHTML. Use DOMPurify or safe alternatives."
        severity: ERROR
        metadata:
            category: security
            cwe: CWE-79

    - id: "eval-injection"
        pattern: eval($DATA)
        pattern-not: eval("trusted_static_string")
        languages: ["javascript"]
        message: "Dangerous use of eval() detected. This can lead to code injection."
        severity: ERROR
        metadata:
            category: security
            cwe: CWE-95
    ''',
            "java": '''
    rules:
    - id: "path-traversal"
        pattern: new File($PATH)
        pattern-not: new File(sanitized_path)
        pattern-inside: |
            class $CLASS {
                ...
            }
        languages: ["java"]
        message: "Potential path traversal vulnerability. Validate and sanitize file paths."
        severity: ERROR
        metadata:
            category: security
            cwe: CWE-22

    - id: "weak-cipher"
        pattern: Cipher.getInstance("DES")
        languages: ["java"]
        message: "Usage of weak cryptographic algorithm DES detected. Use AES instead."
        severity: ERROR
        metadata:
            category: security
            cwe: CWE-326
    '''
        }

        # Get examples for the current language
        examples = EXAMPLE_RULES.get(language, "")

        # Build the enhanced prompt
        prompt = f"""Analyze the following vulnerability patch and generate a precise Semgrep rule to detect similar vulnerabilities in {language} code.

    CONTEXT:
    Repository: github.com/{patch_info.repo_owner}/{patch_info.repo_name}
    Commit: {patch_info.commit_id}

    PATCH CHANGES:
    {combined_changes}

    SEMGREP PATTERN SYNTAX GUIDE:
    - Use $VARNAME to match any expression
    - Use ... to match any sequence of statements
    - Use |> to pipe patterns together
    - Use pattern-inside to limit matches to specific code blocks
    - Use pattern-not to exclude specific patterns (like the fixed version)
    - Use metavariable-pattern to add constraints on variables

    REQUIRED FIELDS:
    1. id: "{suggested_id}" (must be unique and descriptive)
    2. pattern: Clear pattern matching the vulnerable code structure
    3. languages: ["{language}"]
    4. message: Detailed description of:
    - What the vulnerability is
    - Why it's dangerous
    - How to fix it
    5. severity: One of [ERROR, WARNING, INFO]

    RECOMMENDED FIELDS:
    - pattern-not: Pattern that should not match (e.g., fixed version)
    - pattern-inside: Context pattern for where the rule should match
    - pattern-not-inside: Context pattern for where the rule should not match
    - metadata:
        source-url: github.com/{patch_info.repo_owner}/{patch_info.repo_name}/commit/{patch_info.commit_id}
        category: security
        cwe: [relevant CWE number]
        owasp: [relevant OWASP category]
        references: [links to documentation or standards]
        technology: [{language}]

    IMPORTANT GUIDELINES:
    1. Make patterns as specific as possible to minimize false positives
    2. Include pattern-not for the fixed version when possible
    3. Add relevant metadata like CWE numbers and OWASP categories
    4. Write clear, actionable messages explaining both the problem and solution
    5. Consider different variations of the vulnerable pattern

    EXAMPLES OF HIGH-QUALITY RULES:
    {examples}

    FORMAT YOUR RESPONSE AS A SINGLE YAML DOCUMENT:
    rules:
    - id: "{suggested_id}"
    pattern: [Your pattern here]
    pattern-not: [Fixed version pattern]
    languages: ["{language}"]
    message: [Clear description]
    severity: ERROR
    metadata: [Additional context]

    Remember to adapt the patterns to match the specific vulnerability in the patch while keeping them general enough to catch variations of the same issue."""

        if error_feedback:
            prompt += f"\n\nPREVIOUS ERROR TO FIX:\n{error_feedback}\nEnsure your next attempt addresses these issues."
            
        return prompt