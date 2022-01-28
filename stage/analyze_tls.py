import glob
import json
import socket
import subprocess
from os import path

from termcolor import colored


def analyze_tls(workdir, force=False, force_failed=False):
    """
    Analyze TLS support for the domains extracted from the apps using tls-scan
    :param workdir: the working directory
    :type workdir: str
    :param force: force analysis of TLS, even if the TLS has already been analyzed before
    :type force: bool
    :param force_failed: force re-analysis of TLS for domains which tls-scan previously failed
    :type force_failed: bool
    """
    json_file = path.join(workdir, 'tls.json')

    # Get existing TLS analysis
    tls_configs = {}
    if path.exists(json_file):
        with open(json_file, 'r') as f:
            tls_configs = json.load(f)

    # Load domain name list
    urls_json_files = [file for file in glob.glob(path.join(workdir, 'decompiled', '*', 'urls_analyzed.json')) if path.isfile(file)]
    domains = set()
    for urls_json_file in urls_json_files:
        with open(urls_json_file, 'r') as f:
            data = json.load(f)
            for domain in data['domains']:
                # Only analyze domains that haven't been analyzed before, unless forced otherwise
                if domain in tls_configs and not force and not (force_failed and (domain not in tls_configs or tls_configs[domain] is False)):
                    print(colored(f'Skipping analysis of TLS of {domain}, already analyzed', 'yellow'))
                    continue
                else:
                    domains.add(domain)

    # Analyze TLS configurations
    print(f'Analyzing TLS configurations for {len(domains)} domains')

    for domain in domains:
        print(f'Analyzing TLS for {domain}...')

        # Run tls-scan on the domain
        retry = 0
        while retry < 3:
            # We retry the scan several times because experience showed that sometimes the scan fails for unknown reasons
            cmd = f'tls-scan --cacert /etc/ssl/certs/ca-certificates.crt --all -c "{domain}"'
            output = subprocess.check_output(cmd, shell=True).decode('utf-8')
            if output.strip() == '':
                print(colored(f'No TLS configuration found for {domain}', 'yellow'))
                tls_configs[domain] = None
            else:
                try:
                    tls_configs[domain] = json.loads(output)
                    break
                except json.decoder.JSONDecodeError:
                    print(colored(f'Error: could not parse TLS configuration for {domain}', 'red'))
                    print(output)
                    tls_configs[domain] = None

            print(colored(f'Retrying TLS scan for {domain}', 'yellow'))
            retry += 1

        if tls_configs[domain] is None:
            # Test if domain exists
            print(colored(f'TLS scan failed for {domain}, checking domain', 'yellow'))
            try:
                socket.gethostbyname(domain)
                # Domain is not accessible via https, but does exist
                tls_configs[domain] = False
            except:
                # Domain not available
                pass

        # Write intermediate result to json file
        with open(json_file, 'w') as f:
            json.dump(tls_configs, f)

    print(f'TLS configurations saved to {json_file}')
