from bs4 import BeautifulSoup
from urllib.parse import urljoin
from colorama import Fore, Style
import requests

def create_session(args):
    print(f"{Fore.CYAN}[*]{Style.RESET_ALL} Initializing session...")
    session = requests.Session()
    
    if args.headers:
        print(f"{Fore.CYAN}[*]{Style.RESET_ALL} Setting custom headers")
        for header in args.headers:
            if ':' in header:
                key, value = header.split(':', 1)
                session.headers[key.strip()] = value.strip()
                
    if args.auth:
        print(f"{Fore.CYAN}[*]{Style.RESET_ALL} Configuring basic authentication")
        username, password = args.auth.split(':', 1)
        session.auth = (username, password)
    
    if args.cookie:
        print(f"{Fore.CYAN}[*]{Style.RESET_ALL} Setting session cookies")
        # Parse cookie string (e.g. "security=low; PHPSESSID=abc123")
        cookies = {}
        for cookie in args.cookie.split(";"):
            cookie = cookie.strip()
            if "=" in cookie:
                key, value = cookie.split("=", 1)
                cookies[key.strip()] = value.strip()
        # Update the session's cookie jar
        session.cookies.update(cookies)
    
    # Optional: Check for CSRF tokens if POST is used.
    if args.url and args.method == 'POST':
        try:
            print(f"{Fore.CYAN}[*]{Style.RESET_ALL} Checking for CSRF tokens")
            response = session.get(args.url)
            soup = BeautifulSoup(response.text, 'html.parser')
            csrf_input = soup.find('input', {'name': ['csrf_token', '_token']})
            if csrf_input:
                csrf_token = csrf_input.get('value')
                session.headers.update({'X-CSRF-TOKEN': csrf_token})
                print(f"{Fore.GREEN}[+]{Style.RESET_ALL} Found and set CSRF token")
        except Exception as e:
            print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} CSRF handling failed: {str(e)}")
    
    print(f"{Fore.GREEN}[+]{Style.RESET_ALL} Session configured successfully")
    return session


def perform_form_login(session, login_url, auth):
    """
    Attempt a form-based login using the credentials provided in auth (user:pass).
    Uses a heuristic: if the post-login URL differs from the login URL or the login form disappears,
    we assume login succeeded.
    """
    print(f"{Fore.CYAN}[*]{Style.RESET_ALL} Attempting form-based login at {login_url}")
    try:
        response = session.get(login_url)
        soup = BeautifulSoup(response.text, 'html.parser')
        login_form = soup.find('form')
        if not login_form:
            print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} No login form found at {login_url}")
            return False

        # Determine form action
        action = login_form.get('action')
        if action:
            action = urljoin(login_url, action)
        else:
            action = login_url

        # Collect all input fields (including hidden ones)
        form_data = {}
        for input_tag in login_form.find_all('input'):
            name = input_tag.get('name')
            value = input_tag.get('value', '')
            if name:
                form_data[name] = value

        # Override username and password fields with provided auth
        username, password = auth.split(":", 1)
        username_field = None
        password_field = None
        for input_tag in login_form.find_all('input'):
            field_name = input_tag.get('name', '')
            field_type = input_tag.get('type', '')
            if (field_type == 'text' or 'user' in field_name.lower()) and not username_field:
                username_field = field_name
            if (field_type == 'password' or 'pass' in field_name.lower()) and not password_field:
                password_field = field_name

        if username_field:
            form_data[username_field] = username
        else:
            form_data['username'] = username  # Fallback

        if password_field:
            form_data[password_field] = password
        else:
            form_data['password'] = password  # Fallback

        # Submit the login form
        login_response = session.post(action, data=form_data)
        
        # Check if login was successful:
        if login_response.url != login_url:
            print(f"{Fore.GREEN}[+]{Style.RESET_ALL} Login succeeded (redirect detected).")
            return True
        elif not is_login_page(login_response):
            print(f"{Fore.GREEN}[+]{Style.RESET_ALL} Login succeeded (login form not present).")
            return True
        else:
            print(f"{Fore.RED}[!]{Style.RESET_ALL} Login appears unsuccessful.")
            return False

    except Exception as e:
        print(f"{Fore.RED}[!]{Style.RESET_ALL} Exception during login: {str(e)}")
        return False

def is_login_page(response):
    """
    Helper to check if the response appears to be a login page.
    """
    try:
        soup = BeautifulSoup(response.content, 'html5lib')
        return bool(soup.find('input', {'type': 'password'}))
    except Exception:
        return False
        
def create_session_from_cookies(cookies):
    """Create new session with existing cookies"""
    session = requests.Session()
    session.cookies.update(cookies)
    return session