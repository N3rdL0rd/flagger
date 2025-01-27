from abc import ABC, abstractmethod
from typing import List, Optional

class Backend(ABC):
    @abstractmethod
    def __init__(self, url: str, token: Optional[str] = None):
        pass
    
    @abstractmethod
    def get_challenges(self) -> List[str]:
        pass

    @abstractmethod
    def submit_flag(self, flag: str, challenge: str) -> bool:
        pass

from .ctfd import CtfdBackend
from .zeroctf import ZeroCtfBackend
from .ctfx import CtfxBackend