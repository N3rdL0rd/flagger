from . import Backend
from typing import Optional, List
import requests

class CtfdBackend(Backend):
    def __init__(self, url: str, token: Optional[str] = None):
        if not token:
            raise ValueError("CtfdBackend requires a token")
        self.url = url
        self.token = token
        s = requests.Session()
        s.headers.update({"Authorization": f"Token {token}"})
        self.session = s
        self.headers = {
            "Content-Type": "application/json",
        }
        self._test_connection()
        
    def url_for(self, path: str) -> str:
        return (self.url + path).strip("/")
        
    def _test_connection(self):
        r = self.session.get(self.url_for("challenges"), headers=self.headers)
        try:
            r.raise_for_status()
        except requests.HTTPError as e:
            print(f"Error connecting to CTFd: {e}")
            print(r.text)
            raise

    def get_challenges(self) -> List[str]:
        r = self.session.get(self.url_for("challenges"), headers=self.headers)
        r.raise_for_status()
        return [c["name"] for c in r.json()["data"]]
    
    def submit_flag(self, flag: str, challenge: str) -> bool:
        r = self.session.get(self.url_for("challenges"), headers=self.headers)
        r.raise_for_status()
        challenge_id = None
        for c in r.json()["data"]:
            if c["name"] == challenge:
                challenge_id = c["id"]
                break
        if not challenge_id:
            raise ValueError(f"Challenge {challenge} not found")
        data = {
            "challenge_id": challenge_id,
            "submission": flag
        }
        r = self.session.post(self.url_for("challenges/attempt"), headers=self.headers, json=data)
        r.raise_for_status()
        res = r.json()
        if res["success"]:
            if res["data"]["status"] == "correct":
                return True
            return False
        return False
