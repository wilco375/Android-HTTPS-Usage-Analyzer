import glob
import json
from os import path
from util.apps import get_top_apps, get_bottom_apps, get_cleartext_traffic_usage
from util.dict import add_or_set
from util.plotting import plot_bar_chart


def calculate_statistics(workdir):
    """
    Calculate statistics on HTTPS and TLS usage and configuration
    :param workdir: working directory
    :type workdir: str
    """
    # Define dictionary that stores all statistics
    statistics = {}

    # Get statistics for HTTP/HTTPS usage
    _get_https_statistics(workdir, statistics)

    # Get statistics for TLS usage
    _get_tls_statistics(workdir, statistics)

    # Get statistics for usesCleartextTraffic flag
    _get_cleartext_traffic_statistics(workdir, statistics)

    # Display statistics for HTTP/HTTPS usage in apps and domains
    _plot_statistics(statistics)


def _get_https_statistics(workdir, statistics):
    """
    Calculate statistics for HTTP/HTTPS usage in apps and domains
    Will add calculated statistics to the statistics dictionary
    :param workdir: working directory
    :type workdir: str
    :param statistics: statistics dictionary
    :type statistics: dict
    """
    # Enumerate JSON files of applications containing URLs
    urls_json_files = [file for file in glob.glob(path.join(workdir, 'decompiled', '*', 'urls_analyzed.json')) if path.isfile(file)]

    # Get top and bottom apps
    top_bottom_apps_count = 50
    top_apps = get_top_apps(workdir, top_bottom_apps_count)
    bottom_apps = get_bottom_apps(workdir, top_bottom_apps_count)

    # Variables to be populated with statistics
    statistics.update({
        'apps': {
            'label': f'HTTP/HTTPS usage apps',
            'axis': 'Apps',
            'total': len(urls_json_files),
            'http': 0,
            'https': 0,
        },
        'top_apps': {
            'label': f'HTTP/HTTPS usage in top {top_bottom_apps_count} apps',
            'axis': 'Apps',
            'total': top_bottom_apps_count,
            'http': 0,
            'https': 0,
        },
        'bottom_apps': {
            'label': f'HTTP/HTTPS usage in bottom {top_bottom_apps_count} apps',
            'axis': 'Apps',
            'total': top_bottom_apps_count,
            'http': 0,
            'https': 0,
        },
        'http_domains': set(),  # Set of domains using HTTP in some application
        'https_domains': set()  # Set of domains using HTTPS in some application
    })

    # Loop through JSON files of applications containing URLs, and gather statistics
    for urls_json_file in urls_json_files:
        # Load the URL information from the JSON file
        with open(urls_json_file, 'r') as f:
            data = json.load(f)

        package_id = path.basename(path.dirname(urls_json_file))

        # HTTP / HTTPS usage of apps
        if data['url_https_count'] == 0 and data['url_http_count'] != 0:
            statistics['apps']['http'] += 1
            if package_id in top_apps:
                statistics['top_apps']['http'] += 1
            if package_id in bottom_apps:
                statistics['bottom_apps']['http'] += 1
        elif data['url_https_count'] != 0 and data['url_http_count'] == 0:
            statistics['apps']['https'] += 1
            if package_id in top_apps:
                statistics['top_apps']['https'] += 1
            if package_id in bottom_apps:
                statistics['bottom_apps']['https'] += 1

        # HTTP / HTTPS usage for domains
        for url in data['urls']:
            if url['https']:
                statistics['https_domains'].add(url['domain'])
            else:
                statistics['http_domains'].add(url['domain'])

    # Split HTTP and HTTPS domain list into HTTP only, mixed and HTTPS lists
    statistics['http_only_domains'] = statistics['http_domains'] - statistics['https_domains']  # Domains that only use HTTP
    statistics['https_only_domains'] = statistics['https_domains'] - statistics['http_domains']  # Domains that only use HTTPS
    statistics['mixed_domains'] = statistics['http_domains'].intersection(statistics['https_domains'])  # Domains that use HTTP in some apps and HTTPS in other apps
    statistics['domains'] = {
        'label': 'HTTP/HTTPS usage for domains',
        'axis': 'Domains',
        'total': len(statistics['http_only_domains'].union(statistics['https_only_domains'])),
        'http': len(statistics['http_only_domains']),
        'https': len(statistics['http_only_domains']),
    }


def _get_tls_statistics(workdir, statistics):
    """
    Calculate statistics for TLS usage and configuration of domains
    Will add calculated statistics to the statistics dictionary
    :param workdir: working directory
    :type workdir: str
    :param statistics: statistics dictionary
    :type statistics: dict
    """
    # Get results of TLS scans from JSON file
    tls_json_file = path.join(workdir, 'tls.json')
    with open(tls_json_file, 'r') as f:
        tls_data = json.load(f)

    # Variables to be populated with statistics
    statistics.update({
        'tls': {
            'unresolved_domains': 0,    # Number of domains that failed to resolve
            'no_tls_http_domains': 0,   # Number of domains using HTTP that do not have a TLS configuration
            'tls_http_domains': 0,      # Number of domains using HTTP that do have a TLS configuration
            'no_tls_mixed_domains': 0,  # Number of domains that use HTTP in some and HTTPS in other apps that do not have a TLS configuration
            'tls_mixed_domains': 0,     # Number of domains that use HTTP in some and HTTPS in other apps that do have a TLS configuration
            'no_tls_https_domains': 0,  # Number of domains that use HTTPS that do not have a TLS configuration
            'tls_https_domains': 0,     # Number of domains that use HTTPS that do  have a TLS configuration
        },

        'domains_certificate_issues': {  # Certificate errors
            'Valid': 0
        },

        'domains_tls_configs': {}  # Number of domains that support a given TLS version
    })

    # TLS configuration for HTTP/mixed/HTTPS only domains
    for key in ['http', 'mixed', 'https']:
        for domain in statistics['mixed_domains' if key == 'mixed' else f'{key}_only_domains']:
            if tls_data[domain] is None:
                statistics['tls']['unresolved_domains'] += 1
            elif tls_data[domain] is False:
                statistics['tls'][f'no_tls_{key}_domains'] += 1
            else:
                statistics['tls'][f'tls_{key}_domains'] += 1

    # TLS versions and certificate errors
    for domain_tls in tls_data.values():
        if domain_tls is None or domain_tls is False:
            continue

        # TLS versions
        tls_support = [tls_version[len('TLSv'):].replace('_', '.')
                       for tls_version in domain_tls['tlsVersions']
                       if tls_version[:len('TLS')] == 'TLS']
        for tls_version in tls_support:
            add_or_set(statistics['domains_tls_configs'], tls_version)

        # TLS certificate errors
        if domain_tls['verifyCertResult'] is True:
            statistics['domains_certificate_issues']['Valid'] += 1
        else:
            add_or_set(statistics['domains_certificate_issues'], domain_tls['verifyCertError'])


def _get_cleartext_traffic_statistics(workdir, statistics):
    """
    Calculate statistics for usesCleartextTraffic flag usage in apps
    Will add calculated statistics to the statistics dictionary
    :param workdir: working directory
    :type workdir: str
    :param statistics: statistics dictionary
    :type statistics: dict
    """
    (can_use_cleartext, cannot_use_cleartext) = get_cleartext_traffic_usage(workdir)
    statistics.update({
        'can_use_cleartext': can_use_cleartext,
        'cannot_use_cleartext': cannot_use_cleartext,
    })


def _plot_statistics(statistics):
    """
    Plot statistics as bar charts using matplotlib
    :param statistics: statistics to plot
    :type statistics: dict
    """
    for key in ['apps', 'top_apps', 'bottom_apps', 'domains']:
        labels = ['HTTP only', 'Mixed', 'HTTPS only']
        values = [statistics[key]['http'], statistics[key]['total'] - statistics[key]['http'] - statistics[key]['https'], statistics[key]['https']]
        plot_bar_chart(labels, values, statistics[key]['axis'], statistics[key]['label'])

    # Display statistics for TLS configuration of domains
    labels = ['Unresolved', 'No TLS, using HTTP', 'TLS, using HTTP', 'No TLS, using Mixed', 'TLS, using Mixed', 'No TLS, using HTTPS', 'TLS, using HTTPS']
    values = list(statistics['tls'].values())
    plot_bar_chart(labels, values, 'Domains', 'TLS configuration for domains')

    # Display statistics for TLS certificate errors
    labels = list(statistics['domains_certificate_issues'].keys())
    values = list(statistics['domains_certificate_issues'].values())
    plot_bar_chart(labels, values, 'Domains', 'TLS certificate errors of TLS supporting domains', True)

    # Display statistics for TLS versions
    labels = list(statistics['domains_tls_configs'].keys())
    values = list(statistics['domains_tls_configs'].values())
    plot_bar_chart(labels, values, 'Domains', 'TLS versions supported by domains')

    # Display statistics for cleartext traffic usage
    labels = ['Cleartext traffic', 'No cleartext traffic']
    values = [statistics['can_use_cleartext'], statistics['cannot_use_cleartext']]
    plot_bar_chart(labels, values, 'Apps', 'Usage of usesCleartextTraffic flag')
