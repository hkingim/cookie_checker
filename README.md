# cookie_checker
Cookie checker is a python script that checks and flags insecure cookies on target website(s).

## Install libraries needed using pip

```bash
pip install -r requirements.txt
```
## How to Run

```bash
python3 cookie_checker.py -u <target>
```

## Usage

```
usage: cookie_checker.py [-h] (-u URL_TARGET | -f FILE_TARGET) [-d] [-o OUTPUT_FILE]

Check for insecure cookies on target website(s).

options:
  -h, --help            show this help message and exit
  -u URL_TARGET, --url URL_TARGET
                        Target URL.
  -f FILE_TARGET, --file FILE_TARGET
                        File path containing list of targets.
  -d, --disable-ssl-verification
                        Disable SSL certificate verification.
  -o OUTPUT_FILE, --output OUTPUT_FILE
                        Output file to save the results.
```
