from . import Backend
from typing import Optional, List
import requests

class ZeroCtfBackend(Backend):
    def __init__(self, url: str, token: Optional[str] = None):
        self.url = url
        self.scoreboard_url = url + "data/scoreboard_1.json"
        self._test_connection()
        
    def _test_connection(self):
        r = requests.get(self.scoreboard_url)
        try:
            r.raise_for_status()
        except requests.HTTPError as e:
            print(f"Error connecting to ZeroCtf: {e}")
            raise
    
    def get_challenges(self) -> List[str]:
        r = requests.get(self.scoreboard_url)
        r.raise_for_status()
        res = r.json()["problems"]
        return [c["title"] for c in res]
    
    def submit_flag(self, flag, challenge) -> bool:
        """
        Not implemented.
        """
        return True