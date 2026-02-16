from dataclasses import dataclass, field
from pathlib import Path
import os
from cache_manager import CacheManager

@dataclass
class Config:
    rules_dir :Path = Path("rules")
    generated_rules_dir: Path = Path("generated_rules")
    patches_dir: Path = Path("cvedataset-patches")
    repos_cache_dir: Path = Path("cache/repos")
    max_files_changed: int = 1
    max_retries: int = 8
    llm_provider: str = os.getenv("LLM_PROVIDER", "anthropic")
    llm_api_key: str = ""
    llm_model: str = ""
    llm_base_url: str = ""
    cache_manager: CacheManager = field(init=False)

    def __post_init__(self):
        self.cache_manager = CacheManager(self.repos_cache_dir)