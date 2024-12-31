from typing import Dict, List, Any
from abc import ABC, abstractmethod
from dataclasses import dataclass

@dataclass
class Flag:
    flag: str
    origin: str
    context: str

class Sniffer(ABC):
    def __init__(self, global_config: Dict[str, Any], config: Dict[str, Any]):
        self.global_config = global_config
        self.config = config
    
    @abstractmethod
    def sniff(self) -> List[Flag]:
        pass

def consolidate_flags(flags: List[Flag]) -> List[Flag]:
    consolidated = {}
    for flag in flags:
        if flag.flag in consolidated:
            consolidated[flag.flag].origin += f", {flag.origin}"
            consolidated[flag.flag].context += f" {flag.context}"
        else:
            consolidated[flag.flag] = Flag(flag.flag, flag.origin, flag.context)
    return list(consolidated.values())

from .github import GithubSniffer
from .duckduckgo import DuckSniffer

ALL_SNIFFERS = [GithubSniffer, DuckSniffer]