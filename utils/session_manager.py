from bs4 import BeautifulSoup
from urllib.parse import urljoin
from colorama import Fore, Style
import requests

class SessionManager:
    def __init__(self):
        self.session = requests.Session()
        self.is_authenticated = False

    def configure_session(self, args):
        """Configure session with headers, cookies, and authentication"""
        print(f"{Fore.CYAN}[*]{Style.RESET_ALL} Initializing session...")
        
        self._set_headers(args)
        self._set_cookies(args)
        
        if args.url:
            # Perform initial check and authentication
            self._handle_authentication(args)
            print(f"{Fore.GREEN}[+]{Style.RESET_ALL} Session configured successfully")
            return self.session
        else:
            print(f"{Fore.RED}[!]{Style.RESET_ALL} no url provided check --help to see the usage")
            exit(1)
       

    def _set_headers(self, args):
        """Set custom headers in session"""
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Connection': 'keep-alive',
            })
        if args.headers:
            print(f"{Fore.CYAN}[*]{Style.RESET_ALL} Setting custom headers")
            for header in args.headers:
                if ':' in header:
                    key, value = header.split(':', 1)
                    self.session.headers[key.strip()] = value.strip()


    def _set_cookies(self, args):
        """Set session cookies"""
        if args.cookie:
            print(f"{Fore.CYAN}[*]{Style.RESET_ALL} Setting session cookies")
            cookies = {}
            for cookie in args.cookie.split(";"):
                if "=" in cookie:
                    key, value = cookie.split("=", 1)
                    cookies[key.strip()] = value.strip()
            self.session.cookies.update(cookies)

    def _handle_authentication(self, args):
        """Handle authentication globally before any operations"""
        try:
            # First, check if authentication is needed
            print(f"{Fore.CYAN}[*]{Style.RESET_ALL} Checking authentication status...")
            initial_response = self.session.get(args.url)
           
            # Check if we're on a login page or if authentication is needed
            if self._is_login_page(initial_response):
                if not args.auth:
                    print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} Login page detected but no credentials provided")
                    print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} Use --auth username:password to authenticate")
                    return False
                
                print(f"{Fore.CYAN}[*]{Style.RESET_ALL} Login page detected, attempting authentication")
                if self._perform_login(initial_response.url, args.auth):
                    self.is_authenticated = True
                    
                    # Verify authentication
                    verify_response = self.session.get(args.url)
                    if not self._is_login_page(verify_response):
                        print(f"{Fore.GREEN}[+]{Style.RESET_ALL} Authentication successful")
                        return True
                    else:
                        print(f"{Fore.RED}[!]{Style.RESET_ALL} Authentication failed - still on login page")
                        return False
            else:
                print(f"{Fore.GREEN}[+]{Style.RESET_ALL} No authentication required or already authenticated")
                self.is_authenticated = True
                return True
                
        except Exception as e:
            print(f"{Fore.RED}[!]{Style.RESET_ALL} Authentication error: {str(e)}")
            return False

    def _is_login_page(self, response):
        """Check if the current page is a login page"""
        try:
            soup = BeautifulSoup(response.content, 'html5lib')
            
            login_indicators = {
                'input': {'type': 'password'},
                'button': {'type': 'submit', 'text': ['Login', 'Sign in', 'Log in']}
            }
            
            for tag, attrs in login_indicators.items():
                for attr, values in attrs.items():
                    if isinstance(values, list):
                        for value in values:
                            if soup.find(tag, {attr: value}) or \
                               soup.find(tag, text=re.compile(value, re.I)):
                                return True
                    else:
                        if soup.find(tag, {attr: values}):
                            return True
            
            return False
            
        except Exception:
            return False

    def _perform_login(self, login_url, auth):
        """Perform form-based login"""
        try:
            response = self.session.get(login_url)
            soup = BeautifulSoup(response.text, 'html5lib')
            login_form = soup.find('form')
            
            if not login_form:
                print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} No login form found")
                return False

            # Get form action URL
            action = login_form.get('action', '')
            action_url = urljoin(login_url, action) if action else login_url

            # Extract all form fields
            form_data = {}
            for input_tag in login_form.find_all('input'):
                name = input_tag.get('name')
                value = input_tag.get('value', '')
                if name:
                    form_data[name] = value

            # Add authentication credentials
            username, password = auth.split(':', 1)
            username_field = next((input_tag.get('name') for input_tag in login_form.find_all('input')
                                if input_tag.get('type') in ['text', 'email'] or 
                                'user' in input_tag.get('name', '').lower()), 'username')
            password_field = next((input_tag.get('name') for input_tag in login_form.find_all('input')
                                if input_tag.get('type') == 'password'), 'password')

            form_data[username_field] = username
            form_data[password_field] = password

            # Submit login form
            login_response = self.session.post(action_url, data=form_data)
            return login_response.status_code == 200
            
        except Exception as e:
            print(f"{Fore.RED}[!]{Style.RESET_ALL} Login error: {str(e)}")
            return False