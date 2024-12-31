from . import Backend
from typing import Optional, List
import requests
import json

class CtfxBackend(Backend):
    def __init__(self, url: str, username: str, password: str):
        self.url = url.rstrip('/') + '/api'
        self.session = requests.Session()

        login_data = {
            'action': 'login',
            'email': username,
            'password': password
        }
        r = self.session.post(self.url, data=login_data)
        if 'Wrong email or password' in r.text:
            raise ValueError("Invalid login credentials")

        r = self.session.get(self.url + '?get=xsrf_token')
        self.xsrf_token = r.text

    def get_challenges(self) -> List[str]:
        r = self.session.get(self.url + '?get=challenges')
        challenges = json.loads(r.text)
        return [c['title'] for c in challenges]

    def submit_flag(self, flag: str, challenge: str) -> bool:
        r = self.session.get(self.url + '?get=challenges')
        challenges = json.loads(r.text)
        challenge_id = None
        for c in challenges:
            if c['title'] == challenge:
                challenge_id = c['id']
                break
        
        if not challenge_id:
            raise ValueError(f"Challenge {challenge} not found")

        submit_data = {
            'action': 'submit_flag',
            'challenge': challenge_id,
            'flag': flag,
            'xsrf_token': self.xsrf_token
        }
        r = self.session.post(self.url, data=submit_data)
        return 'Challenge solved!' in r.text