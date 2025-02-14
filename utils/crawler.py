from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs
from collections import deque
import re
from colorama import Fore, Style
from utils import session_manager

class AdvancedCrawler:
    def __init__(self, session, start_url, max_urls=30, test_type=None, auth=None):
        self.session = session
        self.start_url = start_url
        self.max_urls = max_urls
        self.test_type = test_type
        self.auth = auth
        self.visited = set()
        self.to_visit = deque([start_url])
        self.domain = urlparse(start_url).netloc
        self.js_pattern = re.compile(r'(?:fetch|axios\.get|XMLHttpRequest)\([\"\'](.*?)[\"\']')
        self.total_discovered = 0
        self.logged_in = False
        self.targets = []
        self.form_count = 0
        self.input_count = 0

    def is_valid_url(self, url):
        parsed = urlparse(url)
        if parsed.netloc != self.domain:
            return False
        excluded_patterns = [
            '/logout', '/static/', '/images/', '/css/', '/js/',
            '.jpg', '.png', '.gif', '.svg', '.webp','.ico'
        ]
        if any(pattern in parsed.path.lower() for pattern in excluded_patterns):
            return False
        return True

    def extract_parameters(self, form):
        params = []
        for input_tag in form.find_all(['input', 'textarea', 'select']):
            self.input_count += 1
            param_name = input_tag.get('name')
            param_type = input_tag.get('type', 'text').lower()
            
            if param_name:
                params.append({
                    'name': param_name,
                    'type': 'POST' if form.get('method', '').upper() == 'POST' else 'GET',
                    'html_type': param_type,
                    'tag': input_tag.name
                })
        return params

    def extract_links(self, response):
        soup = BeautifulSoup(response.content, 'html5lib')
        links = set()

        # Process all forms (including non-LFI relevant ones)
        forms = soup.find_all('form')
        print(f"{Fore.CYAN}[*]{Style.RESET_ALL} Found {len(forms)} forms at {response.url}")
        
        for form in forms:
            self.form_count += 1
            form_action = form.get('action') or response.url
            full_url = urljoin(response.url, form_action)
            
            if self.is_valid_url(full_url):
                params = self.extract_parameters(form)
                if params:
                    print(f"{Fore.GREEN}[+]{Style.RESET_ALL} Form {self.form_count} has {len(params)} parameters")
                    self.targets.append({
                        'url': full_url,
                        'method': form.get('method', 'GET').upper(),
                        'params': params,
                        'source': 'form'
                    })

        # Process links and URL parameters
        for tag in soup.find_all(['a', 'link']):
            url = tag.get('href') or tag.get('src')
            if url:
                full_url = urljoin(response.url, url)
                if self.is_valid_url(full_url):
                    links.add(full_url)
                    parsed = urlparse(full_url)
                    query_params = parse_qs(parsed.query)
                    
                    if query_params:
                        params = [{'name': p, 'type': 'GET', 'html_type': 'url', 'tag': 'a'} 
                                for p in query_params.keys()]
                        self.targets.append({
                            'url': full_url,
                            'method': 'GET',
                            'params': params,
                            'source': 'url'
                        })

        return links

    def handle_login(self, response):
        if self.auth and not self.logged_in:
            print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} Detected potential login page at {response.url}")
            if session_manager.perform_form_login(self.session, response.url, self.auth):
                self.logged_in = True
                print(f"{Fore.GREEN}[+]{Style.RESET_ALL} Successfully authenticated! Re-fetching start URL")
                try:
                    new_response = self.session.get(self.start_url, timeout=5)
                    return new_response
                except Exception as e:
                    print(f"{Fore.RED}[!]{Style.RESET_ALL} Error re-fetching start URL: {str(e)}")
        return response

    def crawl(self):
        print(f"\n{Fore.CYAN}[*]{Style.RESET_ALL} Starting crawler at {self.start_url}")
        print(f"{Fore.CYAN}[*]{Style.RESET_ALL} Maximum URLs to crawl: {self.max_urls}")
        
        while self.to_visit and len(self.visited) < self.max_urls:
            url = self.to_visit.popleft()
            if url in self.visited:
                continue

            try:
                print(f"{Fore.CYAN}[>]{Style.RESET_ALL} Crawling: {url}")
                response = self.session.get(url, timeout=5)
                
                # Handle login pages and authentication
                response = self.handle_login(response)
                
                self.visited.add(url)
                
                if response.status_code == 200:
                    # Extract content from successful responses
                    soup = BeautifulSoup(response.content, 'html5lib')
                    
                    # Check for login form even after auth
                    if not self.logged_in and soup.find('input', {'type': 'password'}):
                        print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} Login form detected but no auth credentials provided")
                    
                    new_links = list(self.extract_links(response))
                    self.total_discovered += len(new_links)
                    self.to_visit.extend([link for link in new_links if link not in self.visited])

            except Exception as e:
                print(f"{Fore.RED}[!]{Style.RESET_ALL} Error crawling {url}: {str(e)}")

        print(f"\n{Fore.GREEN}[+]{Style.RESET_ALL} Crawling completed!")
        print(f"{Fore.CYAN}[*]{Style.RESET_ALL} Total visited URLs: {len(self.visited)}")
        print(f"{Fore.CYAN}[*]{Style.RESET_ALL} Forms processed: {self.form_count}")
        print(f"{Fore.CYAN}[*]{Style.RESET_ALL} Input fields found: {self.input_count}")
        print(f"{Fore.CYAN}[*]{Style.RESET_ALL} Testable parameters found: {sum(len(t['params']) for t in self.targets)}")
        
        return self.targets