from pathlib import Path
import yaml
import logging
from typing import List, Dict, Set
import argparse
from sentence_transformers import SentenceTransformer
import numpy as np
from dataclasses import dataclass
import torch
from collections import defaultdict
import shutil
import json
from llm_provider import LLMProvider
import os

@dataclass
class RuleStats:
    total_rules: int = 0
    duplicate_rules: int = 0
    trivial_rules: int = 0
    overly_specific_rules: int = 0
    accepted_rules: int = 0

class RuleFilter:
    def __init__(self, input_dir: Path, output_dir: Path, model_name: str = 'all-MiniLM-L6-v2'):
        self.input_dir = input_dir
        self.output_dir = output_dir
        self.llm = LLMProvider()
        self.stats = defaultdict(RuleStats)
        self.embeddings_cache = {}
        
        # Initialize the sentence transformer model
        self.embedding_model = SentenceTransformer(model_name)
        if torch.cuda.is_available():
            self.embedding_model = self.embedding_model.to('cuda')
        
    def load_rules(self) -> Dict[str, List[dict]]:
        """Load all rules grouped by language."""
        rules_by_language = defaultdict(list)
        
        for lang_dir in self.input_dir.iterdir():
            if not lang_dir.is_dir():
                continue
                
            language = lang_dir.name
            for rule_file in lang_dir.glob("*.yml"):
                try:
                    with open(rule_file) as f:
                        rule_data = yaml.safe_load(f)
                        if rule_data and "rules" in rule_data:
                            for rule in rule_data["rules"]:
                                rules_by_language[language].append(rule)
                                self.stats[language].total_rules += 1
                except Exception as e:
                    logging.error(f"Error loading rule file {rule_file}: {e}")
                    
        return rules_by_language

    def get_embedding(self, text: str) -> np.ndarray:
        """Get embedding for text using sentence-transformers, using cache if available."""
        if text in self.embeddings_cache:
            return self.embeddings_cache[text]
            
        try:
            # Generate embedding using sentence-transformers
            with torch.no_grad():
                embedding = self.embedding_model.encode(text, convert_to_numpy=True)
            
            self.embeddings_cache[text] = embedding
            return embedding
        except Exception as e:
            logging.error(f"Error getting embedding: {e}")
            # Get the embedding dimension from the model
            embedding_dim = self.embedding_model.get_sentence_embedding_dimension()
            return np.zeros(embedding_dim)  # Return zero vector as fallback

    def is_duplicate(self, rule: dict, existing_rules: List[dict], threshold: float = 0.9) -> bool:
        """Check if rule is a duplicate using embeddings."""
        rule_text = yaml.dump(rule)
        rule_embedding = self.get_embedding(rule_text)
        
        for existing_rule in existing_rules:
            existing_text = yaml.dump(existing_rule)
            existing_embedding = self.get_embedding(existing_text)
            
            similarity = np.dot(rule_embedding, existing_embedding) / (
                np.linalg.norm(rule_embedding) * np.linalg.norm(existing_embedding)
            )
            
            if similarity > threshold:
                return True
                
        return False

    def evaluate_rule_quality(self, rule: dict) -> tuple[bool, str]:
        """Evaluate rule quality using LLM."""
        try:
            prompt = f"""Evaluate this Semgrep rule for quality and generalizability:

{yaml.dump(rule)}

Key Evaluation Criteria:

1. REJECT if the rule depends on project-specific code:
   - References custom project classes/functions
   - Uses internal project-specific APIs
   - Relies on specific project architecture
   - Example (REJECT): pattern: 'MyCompanyUtils.validateUser($INPUT)'
   - Example (REJECT): pattern: 'CompanyAuthenticator.process($DATA)'
   - Example (ACCEPT): pattern: 'json.loads($USER_INPUT)'

2. ACCEPT only if the rule references:
   - Standard language libraries (e.g., 'os', 'sys' in Python)
   - Common SDKs (e.g., AWS SDK, Google Cloud SDK)
   - Popular open-source libraries (e.g., requests, pandas)
   - Generic programming patterns
   Examples:
   - ACCEPT: pattern: 'requests.get($URL, verify=False)'
   - ACCEPT: pattern: 'subprocess.shell($CMD, shell=True)'
   - ACCEPT: pattern: 'eval($USER_INPUT)'

3. REJECT if overly specific implementation:
   - Uses custom validation methods
   - References internal security wrappers
   - Depends on project-specific sanitizers
   Example (REJECT): 
   - pattern: 'CustomSanitizer.cleanInput($DATA)'
   - pattern: 'MyProjectValidator.checkAuth($TOKEN)'
   Example (ACCEPT):
   - pattern: 'htmlspecialchars($USER_INPUT)'
   - pattern: 'mysqli_real_escape_string($CONN, $INPUT)'

4. REJECT if trivial or exact matches:
   - Matches specific string literals
   - Lacks metavariables
   - Example (REJECT): pattern: 'password123'
   - Example (ACCEPT): pattern: '$PASSWORD = "..."'

5. Rule must be generalizable across:
   - Different projects in the same domain
   - Various implementation styles
   - Multiple frameworks
   Example (REJECT): 
   - pattern: 'MyFramework.Model.findOne($QUERY)'
   Example (ACCEPT):
   - pattern: '$DB.query($UNSAFE_INPUT)'
   - pattern: 'execute($SQL_QUERY)'

Language-Specific Good Examples:

Python:
- ACCEPT: pattern: 'pickle.loads($USER_INPUT)'
- ACCEPT: pattern: 'subprocess.run($CMD, shell=True)'
- ACCEPT: pattern: 'open($FILE_PATH + $USER_INPUT)'

JavaScript:
- ACCEPT: pattern: 'eval($USER_INPUT)'
- ACCEPT: pattern: 'document.write($DATA)'
- ACCEPT: pattern: 'new Function($CODE)'

Java:
- ACCEPT: pattern: 'Runtime.getRuntime().exec($CMD)'
- ACCEPT: pattern: 'Statement.executeQuery($SQL)'
- ACCEPT: pattern: 'new File($PATH + $INPUT)'

Examples of Project-Specific (BAD) Rules:
- pattern: 'CompanyDB.rawQuery($SQL)'
- pattern: 'InternalAuthService.validateToken($TOKEN)'
- pattern: 'ProjectConfig.SECURE_PATHS.includes($PATH)'
- pattern: 'MyCustomFramework.Model.find($QUERY)'
- pattern: 'internal.security.Validator.check($INPUT)'

Respond with exactly two lines:
First line: ACCEPT or REJECT
Second line: Brief reason specifically mentioning if it uses project-specific code or standard libraries"""

            content = self.llm.chat_completion(
                system="You are a security expert evaluating Semgrep rules.",
                user=prompt,
                temperature=0.2,
            )

            if not content:
                return False, "No response from LLM"

            lines = content.strip().split('\n')
            decision = lines[0].strip().upper() == 'ACCEPT'
            reason = lines[1].strip() if len(lines) > 1 else "Unknown reason"
            
            return decision, reason
            
        except Exception as e:
            logging.error(f"Error evaluating rule: {e}")
            return False, str(e)

    def filter_rules(self, rules_by_language: Dict[str, List[dict]]) -> Dict[str, List[dict]]:
        """Filter rules by quality and uniqueness."""
        filtered_rules = defaultdict(list)
        
        for language, rules in rules_by_language.items():
            processed_rules = []
            
            for rule in rules:
                # Check for duplicates
                if self.is_duplicate(rule, processed_rules):
                    self.stats[language].duplicate_rules += 1
                    continue
                
                # Evaluate rule quality
                is_accepted, reason = self.evaluate_rule_quality(rule)
                
                if not is_accepted:
                    if "trivial" in reason.lower():
                        self.stats[language].trivial_rules += 1
                    elif "specific" in reason.lower():
                        self.stats[language].overly_specific_rules += 1
                    continue
                
                processed_rules.append(rule)
                filtered_rules[language].append(rule)
                self.stats[language].accepted_rules += 1
                
        return filtered_rules

    def save_filtered_rules(self, filtered_rules: Dict[str, List[dict]]):
        """Save filtered rules to output directory."""
        for language, rules in filtered_rules.items():
            output_dir = self.output_dir / language
            output_dir.mkdir(parents=True, exist_ok=True)
            
            # Group rules by source repository
            rules_by_repo = defaultdict(list)
            for rule in rules:
                repo = rule.get("metadata", {}).get("source-url", "unknown").split("/")[1]
                rules_by_repo[repo].append(rule)
            
            # Save rules grouped by repo
            for repo, repo_rules in rules_by_repo.items():
                output_file = output_dir / f"{repo}_rules.yml"
                with open(output_file, "w") as f:
                    yaml.dump({"rules": repo_rules}, f, sort_keys=False)

    def print_summary(self):
        """Print summary statistics."""
        print("\nRule Filtering Summary:")
        print("-" * 60)
        
        total_stats = RuleStats()
        
        for language, stats in self.stats.items():
            print(f"\nLanguage: {language}")
            print(f"Total Rules: {stats.total_rules}")
            print(f"Duplicates Removed: {stats.duplicate_rules}")
            print(f"Trivial Rules Removed: {stats.trivial_rules}")
            print(f"Overly Specific Rules Removed: {stats.overly_specific_rules}")
            print(f"Accepted Rules: {stats.accepted_rules}")
            print(f"Acceptance Rate: {(stats.accepted_rules / stats.total_rules * 100):.1f}%")
            
            # Update totals
            total_stats.total_rules += stats.total_rules
            total_stats.duplicate_rules += stats.duplicate_rules
            total_stats.trivial_rules += stats.trivial_rules
            total_stats.overly_specific_rules += stats.overly_specific_rules
            total_stats.accepted_rules += stats.accepted_rules
        
        print("\nOverall Statistics:")
        print("-" * 60)
        print(f"Total Rules Processed: {total_stats.total_rules}")
        print(f"Total Duplicates Removed: {total_stats.duplicate_rules}")
        print(f"Total Trivial Rules Removed: {total_stats.trivial_rules}")
        print(f"Total Overly Specific Rules Removed: {total_stats.overly_specific_rules}")
        print(f"Total Accepted Rules: {total_stats.accepted_rules}")
        print(f"Overall Acceptance Rate: {(total_stats.accepted_rules / total_stats.total_rules * 100):.1f}%")

def main():
    parser = argparse.ArgumentParser(description="Filter and improve generated Semgrep rules")
    
    parser.add_argument(
        "--input-dir",
        type=Path,
        default=Path("generated_rules"),
        help="Directory containing generated rules"
    )
    
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("filtered_rules"),
        help="Directory for filtered rules"
    )
    
    parser.add_argument(
        "--embedding-model",
        default="all-MiniLM-L6-v2",
        help="Sentence-transformers model name for embeddings"
    )
    
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        help="Logging level"
    )
    
    args = parser.parse_args()
    
    # Setup logging
    logging.basicConfig(
        level=getattr(logging, args.log_level.upper()),
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Create output directory
    args.output_dir.mkdir(parents=True, exist_ok=True)
    
    # Initialize and run filter
    rule_filter = RuleFilter(args.input_dir, args.output_dir, args.embedding_model)
    
    # Load rules
    logging.info("Loading rules...")
    rules_by_language = rule_filter.load_rules()
    
    # Filter rules
    logging.info("Filtering rules...")
    filtered_rules = rule_filter.filter_rules(rules_by_language)
    
    # Save filtered rules
    logging.info("Saving filtered rules...")
    rule_filter.save_filtered_rules(filtered_rules)
    
    # Print summary
    rule_filter.print_summary()

if __name__ == "__main__":
    main()
