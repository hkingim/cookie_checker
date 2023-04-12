import re
import requests
import argparse
from termcolor import colored
import datetime

###
#    Cookie Checker
#    Usage: python3 cookie_check.py -u <url>
#    Use -h or --help for more options.
###

# Display banner
def banner():
    print()
    print(colored(f"========================================================", 'blue'))
    print(" > cookie_checker.py .................................. ")
    print(colored(f"--------------------------------------------------------", 'blue'))
    print(" Simple tool to check for insecure cookies on a website ")
    print(colored(f"========================================================", 'blue'))
    print()

# Check url or targets
def check_url(url, disable_ssl_verification):
    # Disable ssl verification
    if disable_ssl_verification:
        requests.packages.urllib3.disable_warnings()
    if not url.startswith('http://') and not url.startswith('https://'):
        http_url = f"http://{url}"
        https_url = f"https://{url}"
        check_cookie(http_url, disable_ssl_verification)
        check_cookie(https_url, disable_ssl_verification)
    else:
        check_cookie(url, disable_ssl_verification)

# Check cookies
def check_cookie(url, disable_ssl_verification):
    try:
        response = requests.get(url, verify=not disable_ssl_verification)
        cookies = response.cookies
        if cookies:
            print(colored(f"\n[*] Cookies found in {url}:", 'blue'))
            if url.startswith('http://'):
                print()
                print(colored(f"[!] Target is used under HTTP connection. It's highly recommended to ensure that cookies are transmitted only over HTTPS connections.", 'yellow'))
            for cookie in cookies:
                # Check if there is an expiration date  
                if cookie.expires is not None:    
                    expires_datetime = datetime.datetime.fromtimestamp(cookie.expires)
                    # Convert cookie.expires to readable format
                    expires_str = expires_datetime.strftime("%I:%M:%S %p %m/%d/%Y")
                    # Get the current date
                    current_date = datetime.datetime.now().date()
                    # Get the date part of the expiration datetime
                    expiration_date_only = expires_datetime.date()
                else:
                    expires_str = "None"
                if cookie.has_nonstandard_attr('HttpOnly') or cookie.has_nonstandard_attr('httponly'):
                    httponly_value = True
                else:
                    httponly_value = False
                if cookie.has_nonstandard_attr('SameSite') or cookie.has_nonstandard_attr('samesite'):
                    samesite_value = True
                else:
                    samesite_value = False

                # Print cookie info
                print(colored(f"\n[*] {cookie.name}={cookie.value}; Expires={expires_str}; SameSite={samesite_value}; HttpOnly={httponly_value}; Secure={cookie.secure};", 'cyan'))

                # Check if cookie.expires > today
                if cookie.expires is not None and expiration_date_only > current_date:
                    print(colored(f"[!] Persistent cookie. (Expires: {expires_str})", 'yellow'))
                # Check secure attribute
                if not cookie.secure:
                    print(colored(f"[!] Missing Secure attribute.", 'yellow'))
                # Check httponly attribute
                if not cookie.has_nonstandard_attr('HttpOnly') and not cookie.has_nonstandard_attr('httponly'):
                    print(colored(f"[!] Missing HttpOnly attribute.", 'yellow'))
                # Check samesite attribute
                if not cookie.has_nonstandard_attr('SameSite') and not cookie.has_nonstandard_attr('samesite'): 
                    print(colored(f"[!] Missing SameSite attribute.", 'yellow'))                 
                
            # Collect insecure cookies found         
            insecure_cookies = [ cookie for cookie in cookies if not cookie.secure or not cookie.has_nonstandard_attr('HttpOnly') and not cookie.has_nonstandard_attr('httponly') or not cookie.has_nonstandard_attr('SameSite') and not cookie.has_nonstandard_attr('samesite') or cookie.expires is not None and expiration_date_only > current_date ] 
            if insecure_cookies:
                # Print if insecure cookies found
                print(colored(f"\n\n[!] Insecure cookies found in {url}:", 'yellow'))
            else:
                # Print message if no insecure cookies found  
                print(colored(f"\n\n[*] No insecure cookies found in {url}.", 'green'))
            
        else:
            # Print message if no cookies found
            print(colored(f"\n[*] No cookies found in {url}.", 'blue'))
        print()
    except requests.exceptions.SSLError as e:
        print(colored(f"\n[!] Error: SSL certificate verification failed. To ignore this error, use -d option to disable SSL certificate verification.", 'red'))
        return
    except requests.exceptions.RequestException as e:
#       print(f"\nError: {e}")
        print(colored(f"\n[!] Error: Can't reach {url}. Connection timed out.", 'red'))
        return
    # Print link for reference
    print(colored(f'\nReference: https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies', 'blue'))
    print()

if __name__ == "__main__":
    banner()
    parser = argparse.ArgumentParser(description="Check for insecure cookies on target website(s).")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-u", "--url", dest="url_target", help="Target URL.")
    group.add_argument("-f", "--file", dest="file_target", help="File path containing list of targets.")
    parser.add_argument("-d", "--disable-ssl-verification", action="store_true", help="Disable SSL certificate verification.")
    args = parser.parse_args()


    try:
        # --file target
        if args.file_target:
            with open(args.file_target) as f:
                targets = f.read().splitlines()
            for target in targets:
                check_url(target, args.disable_ssl_verification)
        # --url target
        else:
            check_url(args.url_target, args.disable_ssl_verification)
    except KeyboardInterrupt:
        print(f"\nExiting...")
