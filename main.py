# main.py
import argparse
from urllib.parse import parse_qs
from colorama import init, Fore, Style
from utils import request_parser, session_manager, crawler
from fuzzers import XSS  # Import the fuzzers

# Initialize colorama
init(autoreset=True)

def print_banner():
    banner = f"""
    {Fore.CYAN}╔═╗╦ ╦╔═╗╔═╗╔═╗╦═╗
    {Fore.BLUE}╠═╝║ ║╠═╣╚═╗║╣ ╠╦╝
    {Fore.MAGENTA}╩  ╚═╝╩ ╩╚═╝╚═╝╩╚═
    {Style.RESET_ALL}Web Application Fuzzer v2.0
    """
    print(banner)

def get_targets(args, session):
    targets = []
    
    if args.request_file:
        try:
            print(f"{Fore.CYAN}[*]{Style.RESET_ALL} Parsing request file: {args.request_file}")
            targets.append(request_parser.parse_http_request(args.request_file))
        except Exception as e:
            print(f"{Fore.RED}[!]{Style.RESET_ALL} Failed to parse request file: {str(e)}")

    if args.url:
        headers = {}
        if args.headers:
            print(f"{Fore.CYAN}[*]{Style.RESET_ALL} Parsing custom headers")
            for h in args.headers:
                if ':' in h:
                    key, val = h.split(':', 1)
                    headers[key.strip()] = val.strip()
                else:
                    print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} Invalid header format: {h}")

        data = {}
        if args.data:
            try:
                print(f"{Fore.CYAN}[*]{Style.RESET_ALL} Parsing POST data")
                parsed_data = parse_qs(args.data)
                data = {k: v[0] for k, v in parsed_data.items()}
            except Exception as e:
                print(f"{Fore.RED}[!]{Style.RESET_ALL} Error parsing data: {str(e)}")

        try:
            target = {
                'url': args.url,
                'method': args.method,
                'data': data,
                'headers': headers
            }
            request_parser.validate_target(target)
            targets.append(target)
            print(f"{Fore.GREEN}[+]{Style.RESET_ALL} Valid target configured: {args.url}")
        except ValueError as e:
            print(f"{Fore.RED}[!]{Style.RESET_ALL} Invalid target: {str(e)}")

    if args.crawl and args.url:
        try:
            print(f"{Fore.CYAN}[*]{Style.RESET_ALL} Initializing crawler")
            crawler_instance = crawler.AdvancedCrawler(
                session=session,
                start_url=args.url,
                max_urls=args.max_urls,
                auth=args.auth,
                test_type='lfi' if args.lfi else None
            )
            
            print(f"{Fore.CYAN}[*]{Style.RESET_ALL} Starting crawl operation")
            crawled_targets = crawler_instance.crawl()
            targets.extend(crawled_targets)
            print(f"{Fore.GREEN}[+]{Style.RESET_ALL} Crawling completed. Found {len(crawled_targets)} endpoints")
            
        except Exception as e:
            print(f"{Fore.RED}[!]{Style.RESET_ALL} Crawling failed: {str(e)}")

    return targets

def main():
    print_banner()
    parser = argparse.ArgumentParser(description="Advanced Web Application Fuzzer")
    
    # Input options
    parser.add_argument('--crawl', action='store_true', help='Enable website crawling')
    parser.add_argument('--max-urls', type=int, default=30, help='Maximum URLs to crawl')
    parser.add_argument('-u', '--url', help='Target URL to test')
    parser.add_argument('-X', '--method', default='GET', help='HTTP method')
    parser.add_argument('-d', '--data', help='POST data parameters')
    parser.add_argument('-H', '--headers', action='append', help='Custom headers')
    parser.add_argument('--request-file', help='Path to raw HTTP request file')
    
    # Session options
    parser.add_argument('--cookie', help='Session cookie')
    parser.add_argument('--auth', help='Basic authentication (user:pass)')
    
    # Fuzzer options
    parser.add_argument('--xss', action='store_true', help='Enable XSS fuzzing')
    parser.add_argument('--sqli', action='store_true', help='Enable SQL injection fuzzing')
    parser.add_argument('--lfi', action='store_true', help='Enable LFI fuzzing')
    parser.add_argument('--payload-file', help='Path to a file containing custom XSS payloads', default=None)
    parser.add_argument('-t', '--threads', type=int, default=5, help='Number of threads')

    args = parser.parse_args()
    
    # Initialize components
    session = session_manager.create_session(args)
    targets = get_targets(args, session)
    
    # Run fuzzers
    if args.xss:
        print(f"\n{Fore.CYAN}[*]{Style.RESET_ALL} Starting XSS fuzzing...")
        xss_fuzzer = XSS(session, threads=args.threads)
        
        if args.payload_file:
            try:
                with open(args.payload_file, 'r') as file:
                    custom_payloads = [line.strip() for line in file.readlines()]
                xss_fuzzer.payloads = custom_payloads
            except Exception as e:
                print(f"{Fore.RED}[!]{Style.RESET_ALL} Failed to read payload file: {str(e)}")
                return
        
        results = xss_fuzzer.fuzz(targets)
        
        # Print results
        print(f"\n{Fore.GREEN}[+]{Style.RESET_ALL} XSS Scan Results:")
        for result in results:
            print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} Potential XSS at {result['url']}")
            print(f"   Parameter: {result['param']} | Payload: {result['payload']}")
            print(f"   Status: {result['status']} | Length: {result['length']}\n")

if __name__ == '__main__':
    main()