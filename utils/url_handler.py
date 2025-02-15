from urllib.parse import urlparse, parse_qs, urljoin
from colorama import Fore, Style

class URLHandler:
    def __init__(self, url):
        self.url = url
        self.parsed_url = urlparse(url)
        self.domain = self.parsed_url.netloc
        self.targets = []
        self.total_params = 0


    def is_valid_url(self, url):
        """Validate if URL is within scope and not a static resource"""
        parsed = urlparse(url)
        if parsed.netloc != self.domain:
            return False
            
        excluded_patterns = [
            '/logout', '/static/', '/images/', '/css/', '/js/',
            '.jpg', '.png', '.gif', '.svg', '.webp', '.ico'
        ]
        return not any(pattern in parsed.path.lower() for pattern in excluded_patterns)

    def extract_parameters(self):
        """Extract parameters from URL and create target"""
        # Parse query parameters
        query_params = parse_qs(self.parsed_url.query)
        
        if query_params:
            params = []
            for param_name in query_params.keys():
                params.append({
                    'name': param_name,
                    'type': 'GET',
                    'html_type': 'url',
                    'tag': 'url'
                })
                self.total_params += 1
            
            if params:
                target = {
                    'url': self.url,
                    'method': 'GET',
                    'params': params,
                    'source': 'url'
                }
                self.targets.append(target)
                self._print_found_params(params)
                return True
        
        self._print_no_params_error()
        return False

    def _print_found_params(self, params):
        """Print information about found parameters"""
        print(f"\n{Fore.GREEN}[+]{Style.RESET_ALL} URL Analysis Results:")
        print(f"{Fore.CYAN}[*]{Style.RESET_ALL} Target URL: {self.url}")
        print(f"{Fore.GREEN}[+]{Style.RESET_ALL} Found {len(params)} parameters:")
        for param in params:
            print(f"{Fore.GREEN}[+] {param['name']} ({param['type']})")

    def _print_no_params_error(self):
        """Print error message when no parameters are found"""
        print(f"\n{Fore.RED}[!]{Style.RESET_ALL} No parameters found in URL:")
        print(f"    URL: {self.url}")
        print("\nPossible solutions:")
        print("1. Ensure URL contains query parameters (e.g. ?param=value)")
        print("2. Use crawler mode to discover parameters automatically")
        print("3. Check if URL is correctly formatted")
        print("4. Verify target page is accessible")
        exit(1)

    def get_domain_info(self):
        """Return information about the URL's domain"""
        return {
            'domain': self.domain,
            'scheme': self.parsed_url.scheme,
            'path': self.parsed_url.path,
            'base_url': f"{self.parsed_url.scheme}://{self.domain}"
        }

    def get_targets(self):
        """Return list of discovered targets"""
        return self.targets