from . import Sniffer, Flag

import requests
from urllib.parse import quote
import json
import re
from tqdm import tqdm
import base64
from datetime import datetime

class GithubSniffer(Sniffer):
    def __init__(self, global_config, config):
        super().__init__(global_config, config)
        self.token = global_config["keys"]["github"]
        self.after_date = datetime.strptime(config["start"], "%Y-%m-%dT%H:%M:%SZ")
    
    def sniff(self):
        headers = {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {self.token}",
            "X-GitHub-Api-Version": "2022-11-28"
        }
        search_query = quote(f"{self.config['search']} {self.config['flag_start']} ", safe='')
        
        response = requests.get(
            f"https://api.github.com/search/code?q={search_query}",
            headers=headers
        )
        response.raise_for_status()
        repos = response.json()
        with open('test.json', 'w') as f:
            json.dump(repos, f)
        
        flags = []
        
        for repo in tqdm(repos["items"]):
            commits_url = f"https://api.github.com/repos/{repo['repository']['full_name']}/commits"
            params = {'path': repo['path'], 'per_page': 1}  # Get latest commit only
            commit_response = requests.get(commits_url, headers=headers, params=params)
            commit_response.raise_for_status()
            commits = commit_response.json()
            
            if commits:
                last_modified = datetime.strptime(commits[0]['commit']['committer']['date'], '%Y-%m-%dT%H:%M:%SZ')
                if last_modified < self.after_date:
                    continue

            response = requests.get(
                f"https://api.github.com/repos/{repo['repository']['full_name']}/contents/{repo['path']}",
                headers=headers
            )
            response.raise_for_status()
            content = response.json()
            content = base64.b64decode(content['content']).decode('utf-8')
            r = re.compile(self.config['flag_re'])
            res = r.findall(content)
            for flag in res:
                # get -50/+50 lines around the flag
                flag_line = -1
                for i, line in enumerate(content.splitlines()):
                    if flag in line:
                        flag_line = i
                        break
                if flag_line == -1:
                    continue
                start = max(0, flag_line - 50)
                end = min(len(content.splitlines()), flag_line + 50)
                content = "\n".join(content.splitlines()[start:end])
                flags.append(Flag(flag, f"https://github.com/{repo['repository']['full_name']}", content))

        return flags