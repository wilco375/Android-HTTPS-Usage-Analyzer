import glob
import json
from os import path
from util.apps import get_top_apps, get_bottom_apps, get_cleartext_traffic_usage
from util.plotting import plot_bar_chart


def calculate_statistics(workdir):
    # Enumerate JSON files of applications containing URLs
    urls_json_files = [file for file in glob.glob(path.join(workdir, 'decompiled', '*', 'urls_analyzed.json')) if path.isfile(file)]

    # Get results of TLS scans from JSON file
    tls_json_file = path.join(workdir, 'tls.json')
    with open(tls_json_file, 'r') as f:
        tls_data = json.load(f)

    # Variables to be populated with statistics
    http_only_apps  = 0  # Number of apps that only use HTTP requests
    https_only_apps = 0  # Number of apps that only use HTTPS requests

    http_only_top_apps = 0  # Number of top apps that only use HTTP requests
    https_only_top_apps = 0  # Number of top apps that only use HTTPS requests

    http_only_bottom_apps = 0  # Number of bottom apps that only use HTTP requests
    https_only_bottom_apps = 0  # Number of bottom apps that only use HTTPS requests

    http_domains  = set()  # Set of domains using HTTP in some application
    https_domains = set()  # Set of domains using HTTPS in some application

    # Get top and bottom apps
    top_bottom_apps_count = 50
    top_apps = get_top_apps(workdir, top_bottom_apps_count)
    bottom_apps = get_bottom_apps(workdir, top_bottom_apps_count)

    # Loop through JSON files of applications containing URLs, and gather statistics
    for urls_json_file in urls_json_files:
        # Load the URL information from the JSON file
        with open(urls_json_file, 'r') as f:
            data = json.load(f)

        package_id = path.basename(path.dirname(urls_json_file))

        # HTTP / HTTPS usage of apps
        if data['url_https_count'] == 0 and data['url_http_count'] != 0:
            http_only_apps += 1
            if package_id in top_apps:
                http_only_top_apps += 1
            if package_id in bottom_apps:
                http_only_bottom_apps += 1
        elif data['url_https_count'] != 0 and data['url_http_count'] == 0:
            https_only_apps += 1
            if package_id in top_apps:
                https_only_top_apps += 1
            if package_id in bottom_apps:
                https_only_bottom_apps += 1

        # HTTP / HTTPS usage for domains
        for url in data['urls']:
            if url['https']:
                https_domains.add(url['domain'])
            else:
                http_domains.add(url['domain'])

    # Split HTTP and HTTPS domain list into HTTP only, mixed and HTTPS lists
    http_only_domains = http_domains - https_domains          # Domains that only use HTTP
    https_only_domains = https_domains - http_domains         # Domains that only use HTTPS
    mixed_domains = http_domains.intersection(https_domains)  # Domains that use HTTP in some apps and HTTPS in other apps

    # Variables to be populated with statistics
    unresolved_domains = 0  # Number of domains that failed to resolve
    no_tls_http_domains = 0  # Number of domains using HTTP that do not have a TLS configuration
    tls_http_domains = 0  # Number of domains using HTTP that do have a TLS configuration
    no_tls_mixed_domains = 0  # Number of domains that use HTTP in some and HTTPS in other apps that do not have a TLS configuration
    tls_mixed_domains = 0  # Number of domains that use HTTP in some and HTTPS in other apps that do have a TLS configuration
    no_tls_https_domains = 0  # Number of domains that use HTTPS that do not have a TLS configuration
    tls_https_domains = 0  # Number of domains that use HTTPS that do  have a TLS configuration

    domains_certificate_issues = {
        'Valid': 0
    }

    domains_tls_configs = {}

    # TLS configuration for HTTP only domains
    for domain in http_only_domains:
        if tls_data[domain] is None:
            unresolved_domains += 1
        elif tls_data[domain] is False:
            no_tls_http_domains += 1
        else:
            tls_http_domains += 1

    # TLS configuration for mixed domains
    for domain in mixed_domains:
        if tls_data[domain] is None:
            unresolved_domains += 1
        elif tls_data[domain] is False:
            no_tls_mixed_domains += 1
        else:
            tls_mixed_domains += 1

    # TLS configuration for HTTPS only domains
    for domain in https_only_domains:
        if tls_data[domain] is None:
            unresolved_domains += 1
        elif tls_data[domain] is False:
            no_tls_https_domains += 1
        else:
            tls_https_domains += 1

    for domain_tls in tls_data.values():
        if domain_tls is None or domain_tls is False:
            continue

        if domain_tls['verifyCertResult'] is True:
            domains_certificate_issues['Valid'] += 1
        else:
            if domain_tls['verifyCertError'] not in domains_certificate_issues:
                domains_certificate_issues[domain_tls['verifyCertError']] = 1
            else:
                domains_certificate_issues[domain_tls['verifyCertError']] += 1

        tls_support = [tls_version[len('TLSv'):].replace('_', '.')
                       for tls_version in domain_tls['tlsVersions']
                       if tls_version[:len('TLS')] == 'TLS']
        for tls_version in tls_support:
            if tls_version not in domains_tls_configs:
                domains_tls_configs[tls_version] = 1
            else:
                domains_tls_configs[tls_version] += 1

    (can_use_cleartext, cannot_use_cleartext) = get_cleartext_traffic_usage(workdir)

    # Display statistics for HTTP/HTTPS usage in apps
    labels = ['HTTP only', 'Mixed', 'HTTPS only']
    application_count = len(urls_json_files)
    values = [http_only_apps, application_count - http_only_apps - https_only_apps, https_only_apps]
    plot_bar_chart(labels, values, 'Apps', 'HTTP/HTTPS usage in apps')

    labels = ['HTTP only', 'Mixed', 'HTTPS only']
    values = [http_only_top_apps, top_bottom_apps_count - http_only_top_apps - https_only_top_apps, https_only_top_apps]
    plot_bar_chart(labels, values, 'Apps', f'HTTP/HTTPS usage in top {top_bottom_apps_count} apps')

    labels = ['HTTP only', 'Mixed', 'HTTPS only']
    values = [http_only_bottom_apps, top_bottom_apps_count - http_only_bottom_apps - https_only_bottom_apps, https_only_bottom_apps]
    plot_bar_chart(labels, values, 'Apps', f'HTTP/HTTPS usage in bottom {top_bottom_apps_count} apps')

    # Display statistics for HTTP/HTTPS usage for domains
    labels = ['HTTP only', 'Mixed', 'HTTPS only']
    values = [len(http_only_domains), len(mixed_domains), len(https_only_domains)]
    plot_bar_chart(labels, values, 'Domains', 'HTTP/HTTPS usage for domains')

    # Display statistics for TLS configuration of domains
    labels = ['Unresolved', 'No TLS, using HTTP', 'TLS, using HTTP', 'No TLS, using Mixed', 'TLS, using Mixed', 'No TLS, using HTTPS', 'TLS, using HTTPS']
    values = [unresolved_domains, no_tls_http_domains, tls_http_domains, no_tls_mixed_domains, tls_mixed_domains, no_tls_https_domains, tls_https_domains]
    plot_bar_chart(labels, values, 'Domains', 'TLS configuration for domains')

    # Display statistics for TLS certificate errors
    labels = list(domains_certificate_issues.keys())
    values = list(domains_certificate_issues.values())
    plot_bar_chart(labels, values, 'Domains', 'TLS certificate errors of HTTPS domains', True)

    # Display statistics for TLS versions
    labels = list(domains_tls_configs.keys())
    values = list(domains_tls_configs.values())
    plot_bar_chart(labels, values, 'Domains', 'TLS versions supported by domains')

    # Display statistics for cleartext traffic usage
    labels = ['Cleartext traffic', 'No cleartext traffic']
    values = [can_use_cleartext, cannot_use_cleartext]
    plot_bar_chart(labels, values, 'Apps', 'Usage of usesCleartextTraffic flag')
