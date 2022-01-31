import glob
import json
import socket
import subprocess
from os import path
from util.functions import retry

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
    domains = _extract_domains(tls_configs, workdir, force, force_failed)

    # Analyze TLS configurations
    print(f'Analyzing TLS configurations for {len(domains)} domains')
    for domain in domains:
        print(f'Analyzing TLS for {domain}...')

        # We retry the scan several times because experience showed that sometimes the scan fails for unknown reasons
        tls_config = retry(lambda: _analyze_domain_tls(domain))

        if tls_config is False:
            # Test if domain exists
            print(colored(f'TLS scan failed for {domain}, checking domain', 'yellow'))
            if _domain_reachable(domain):
                # Domain is not accessible via https, but does exist
                tls_configs[domain] = False
            else:
                # Domain not available
                tls_configs[domain] = None
        else:
            tls_configs[domain] = tls_config

        # Write intermediate result to json file
        _save_to_json_file(json_file, tls_configs)

    print(f'TLS configurations saved to {json_file}')


def _extract_domains(tls_configs, workdir, overwrite, retry_failed):
    """
    Extract all used domains from apps
    :param tls_configs: TLS configuration of analyzed domains from previous scans
    :type tls_configs: dict
    :param workdir: working directory
    :type workdir: str
    :param overwrite: re-analyze all domains, overwriting results from previous scans
    :type overwrite: bool
    :param retry_failed: retry analysis of domains which tls-scan previously failed
    :type retry_failed: bool
    :return:
    """
    urls_json_files = [file for file in glob.glob(path.join(workdir, 'decompiled', '*', 'urls_analyzed.json')) if
                       path.isfile(file)]
    domains = set()
    for urls_json_file in urls_json_files:
        with open(urls_json_file, 'r') as f:
            data = json.load(f)
            for domain in data['domains']:
                # Only analyze domains that haven't been analyzed before, unless forced otherwise
                if domain in tls_configs and not overwrite and not (
                        retry_failed and (domain not in tls_configs or tls_configs[domain] is False)):
                    print(colored(f'Skipping analysis of TLS of {domain}, already analyzed', 'yellow'))
                    continue
                else:
                    domains.add(domain)
    return domains


def _analyze_domain_tls(domain):
    """
    Analyze TLS support for the domain using tls-scan
    :param domain: domain to analyze
    :type domain: str
    :return: False if TLS scan failed, TLS configuration otherwise
    :rtype: bool|dict
    """
    cmd = f'tls-scan --cacert /etc/ssl/certs/ca-certificates.crt --all -c "{domain}"'
    output = subprocess.check_output(cmd, shell=True).decode('utf-8')
    if output.strip() == '':
        print(colored(f'No TLS configuration found for {domain}', 'yellow'))
    else:
        try:
            return json.loads(output)
        except json.decoder.JSONDecodeError:
            print(colored(f'Error: could not parse TLS configuration for {domain}', 'red'))
            print(output)

    print(colored(f'Retrying TLS scan for {domain}', 'yellow'))
    return False


def _domain_reachable(domain):
    """
    Check if the given domain is reachable (has a DNS entry)
    :param domain: domain to check
    :type domain: str
    :return: True if domain is reachable, False otherwise
    :rtype: bool
    """
    try:
        socket.gethostbyname(domain)
        return True
    except:
        return False


def _save_to_json_file(json_file, tls_configs):
    """
    Save the analyzed TLS configurations to a JSON file
    :param json_file: URLs JSON file
    :type json_file: str
    :param tls_configs: analyzed TLS configurations
    :type tls_configs: dict
    """
    with open(json_file, 'w') as f:
        json.dump(tls_configs, f)

