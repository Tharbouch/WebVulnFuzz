from urllib.parse import urlparse, parse_qs
import re
from colorama import Fore, Style

def validate_target(target):
    parsed = urlparse(target['url'])
    if not parsed.scheme or not parsed.netloc:
        raise ValueError(f"Invalid URL format: {target['url']}")
    if len(target.get('data', {})) > 100:
        raise ValueError("Excessive number of parameters detected")
    return True

def parse_http_request(file_path):
    try:
        with open(file_path, 'r') as f:
            content = f.read().split('\n\n', 1)
        
        headers_part = content[0]
        body = content[1] if len(content) > 1 else ''

        headers_lines = headers_part.split('\n')
        method, path, _ = headers_lines[0].split()
        
        headers = {}
        host = ''
        for line in headers_lines[1:]:
            if ':' in line:
                key, val = line.split(':', 1)
                key = key.strip()
                val = val.strip()
                headers[key] = val
                if key.lower() == 'host':
                    host = val

        scheme = 'https://' if 'Upgrade-Insecure-Requests' in headers else 'http://'
        url = f"{scheme}{host}{path}"
        data = parse_qs(body) if body else {}

        parsed = {
            'method': method,
            'url': url,
            'headers': headers,
            'data': data
        }
        validate_target(parsed)
        return parsed
    except Exception as e:
        print(f"{Fore.RED}[!]{Style.RESET_ALL} Request parsing failed: {str(e)}")
        raise