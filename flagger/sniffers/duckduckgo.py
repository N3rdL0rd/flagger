from . import Sniffer, Flag
import requests
from datetime import datetime
from tqdm import tqdm
import re
from bs4 import BeautifulSoup
from duckduckgo_search import DDGS
import time

class DuckSniffer(Sniffer):
    def __init__(self, global_config, config):
        super().__init__(global_config, config)
        self.after_date = datetime.strptime(config["start"], "%Y-%m-%dT%H:%M:%SZ")
    
    def sniff(self):
        flags = []
        with DDGS() as ddgs:
            search_query = f"{self.config['search']} {self.config['flag_start']}"
            results = list(ddgs.text(search_query, max_results=100))
            
            if not results:
                return flags

            for item in tqdm(results):
                try:
                    
                    page_response = requests.get(item['url'])
                    page_response.raise_for_status()
                    
                    soup = BeautifulSoup(page_response.text, 'html.parser')
                    content = soup.get_text()
                    
                    r = re.compile(self.config['flag_re'])
                    matches = r.findall(content)
                    
                    for flag in matches:
                        lines = content.splitlines()
                        flag_line = -1
                        for i, line in enumerate(lines):
                            if flag in line:
                                flag_line = i
                                break
                                
                        if flag_line != -1:
                            start = max(0, flag_line - 50)
                            end = min(len(lines), flag_line + 50)
                            context = "\n".join(lines[start:end])
                            flags.append(Flag(flag, item['url'], context))
                
                except (requests.RequestException, KeyError):
                    continue

        return flags