import subprocess
import sys
import os
import time
from os import path
import glob
from termcolor import colored
import re
import json
import shutil
import zipfile
import argparse
import requests
import socket
from bs4 import BeautifulSoup
import numpy as np
import matplotlib.pyplot as plt

workdir = ''


def run():
    parser = argparse.ArgumentParser(description='Analyze HTTP(S) usage in Android apps')

    parser.add_argument('workdir', metavar='WORKING_DIR', type=str,
                        help='working directory containing apk files or an apps.txt file with package ids')

    parser.add_argument('-fs', '--force-scrape', action='store_true', dest='force_scrape',
                        help='force re-scraping of package ids from the Google Play store')
    parser.add_argument('-fdl', '--force-download', action='store_true', dest='force_download_apps',
                        help='force re-downloading of apk files')
    parser.add_argument('-fdc', '--force-decompile', action='store_true', dest='force_decompile',
                        help='force re-decompilation of apk files')
    parser.add_argument('-fe', '--force-extract', action='store_true', dest='force_extract',
                        help='force re-extraction of urls')
    parser.add_argument('-fp', '--force-process', action='store_true', dest='force_process',
                        help='force re-processing of urls')
    parser.add_argument('-fa', '--force-analyze', action='store_true', dest='force_analyze',
                        help='force re-analysis of urls')
    parser.add_argument('-ft', '--force-analyze-tls', action='store_true', dest='force_analyze_tls',
                        help='force re-analysis of the TLS configuration of found domains')
    parser.add_argument('-ftf', '--force-analyze-tls-failed', action='store_true', dest='force_analyze_tls_failed',
                        help='force re-analysis of the TLS configuration of domains where the configuration could previously not be determined')

    parser.add_argument('-so', '--statistics-only', action='store_true', dest='statistics_only',
                        help='only show statistics and skip all other steps')

    parser.add_argument('-u', '--google-username', nargs='?', dest='google_username',
                        help='google username to authenticate with for usage with apkeep to download apps')
    parser.add_argument('-p', '--google-password', nargs='?', dest='google_password',
                        help='google password to authenticate with for usage with apkeep to download apps')

    args = parser.parse_args()

    # Check if working directory is valid
    global workdir
    workdir = args.workdir
    if not path.exists(workdir) or not path.isdir(workdir):
        print(colored('Error: provided working directory does not exist', 'red'))
        sys.exit(1)

    # Run program
    if not args.statistics_only:
        print("=== Extracting top apps from Google Play ===")
        get_app_package_ids(args.force_scrape)

        print("=== Downloading apps ===")
        download_apks(args.force_download_apps, args.google_username, args.google_password)

        print("\n=== Decompiling apps ===")
        decompile_apks(args.force_decompile)

        print("\n=== Extracting URLs ===")
        extract_urls(args.force_extract)

        print("\n=== Processing URLs ===")
        process_urls(args.force_process)

        print("\n=== Analyzing URLs ===")
        analyze_urls(args.force_analyze)

        print("\n=== Analyzing TLS configurations ===")
        analyze_tls(args.force_analyze_tls, args.force_analyze_tls_failed)

    calculate_statistics()


def get_app_package_ids(force=False):
    """
    Scrape the Google Play store for the top apps of each category and save their package ids to a json file
    :param force: force extraction of package ids, even if json file already exists
    """

    # Check if json file already exists
    apps_json = path.join(workdir, 'apps.json')
    if path.exists(apps_json):
        if force:
            # Delete file
            print(colored(f'Deleting existing apk file', 'yellow'))
            os.remove(apps_json)
        else:
            # Skip extraction
            print(colored(f'Skipping extracting of package ids from Google Play, already extracted', 'yellow'))
            return

    # Download the main app web page to extract the categories from
    url = 'https://play.google.com/store/apps'
    response = requests.get(url)

    if not response.ok:
        print(colored('Error: could not retrieve list of categories from Google Play', 'red'))
        return

    # Extract category URLs using a regex
    categories = re.findall('/store/apps/category/[A-Za-z_]+', response.text)
    apps = []
    package_ids = []
    for category_url in categories:
        if 'GAME_' in category_url:
            # Skip game subcategories
            continue

        category = category_url[len('/store/apps/category/'):]
        print(f"Extracting package ids from category {category}")

        # Find the section in the category that has the top apps
        url = f'https://play.google.com{category_url}'
        response = requests.get(url)
        html = BeautifulSoup(response.text, 'html.parser')
        top_apps = html.find(text="Recommended for you")
        if top_apps is None:
            print(colored(f'Warning: could not find top apps section in category {category}', 'yellow'))
            continue

        # Extract the package ids from the top apps section
        url = 'https://play.google.com' + top_apps.find_parent('a').attrs['href']
        response = requests.get(url)
        app_ids = re.findall('(?:"/store/apps/details\?id=)([^"]+)(?:")', response.text)
        index = 1
        for id in app_ids:
            if id in package_ids:
                # Ignore duplicate package ids
                continue

            package_ids.append(id)
            apps.append({
                'index': index,
                'package_id': id,
                'category': category
            })
            index += 1

    # Write package ids to json file
    with open(apps_json, 'w') as f:
        print(f'Package ids saved to {apps_json}')
        json.dump(apps, f)


def download_apks(force=False, google_username=None, google_password=None):
    """
    Download the apks for the top apps using apkeep
    :param force: force downloading of apks, even if apk file already exists
    :param google_username: Google username to use with apkeep to download apks from the Google Play store
    :param google_password: Google password to use with apkeep to download apks from the Google Play store
    """

    # Check if file with apps to download exists
    if not path.exists(path.join(workdir, 'apps.json')):
        print(colored('No apps.json file found, not downloading any apks', 'yellow'))
        return

    # Loop through apps to download
    with open(path.join(workdir, 'apps.json')) as f:
        packages = json.load(f)
    package_ids = [package['package_id'] for package in packages]
    for package_id in package_ids:
        apk_file = path.join(workdir, package_id+'.apk')

        # Check if apk file already exists
        if path.exists(apk_file):
            if force:
                # Delete file
                print(colored(f'Deleting existing apk file', 'yellow'))
                os.remove(apk_file)
            else:
                # Skip app
                print(colored(f'Skipping download of {package_id}, already exists', 'yellow'))
                continue

        # Download apk file using apkeep
        cmd = f'apkeep -a "{package_id}" "{workdir}"'
        if google_username and google_password:
            # Download from the Google Play store if username and password are provided
            cmd += f' -d GooglePlay -u "{google_username}" -p "{google_password}"'

        retry = 0
        while retry < 3:
            success = os.system(cmd)

            if success == 0:
                # Download succeeded, no need to retry
                break

            if google_username and google_password:
                # Download may have hit rate limiting, wait for a bit
                print(colored(f'Failed to download, sleeping for 2 minutes', 'yellow'))
                time.sleep(120)

            retry += 1

        if success != 0:
            print(colored(f'Error: failed to download {path.basename(package_id)}', 'red'))
        else:
            print(f'App downloaded to {workdir}')
            check_apk(package_id, apk_file)


def check_apk(package_id, file):
    """
    Check if the apk file is valid. If it is a split apk, extract the core apk. If invalid, delete the file.
    :param package_id: package id of the app
    :param file: path of file to check
    """

    # Check if apk file exists
    if not path.exists(file):
        print(colored(f'Error: app {package_id} failed to download', 'red'))
        return

    # Check if apk file is a zip file
    if not zipfile.is_zipfile(file):
        print(colored(f'Error: {file} is not a valid apk file, deleting file', 'red'))
        os.remove(file)
        return

    # Open apk as zip file to check if it is a split apk
    split_apk_file = None
    with zipfile.ZipFile(file, 'r') as zf:
        if 'manifest.json' in zf.namelist():
            # Read manifest
            with zf.open('manifest.json') as f:
                manifest = json.load(f)

            # Check if split apk
            if 'split_apks' in manifest:
                # Split apk, get base apk file
                for split_apk in manifest['split_apks']:
                    if split_apk['id'] == 'base':
                        split_apk_file = split_apk['file']

            # Extract base apk from split apk
            if split_apk_file is not None:
                print("Downloaded apk is split apk, extracting base apk")
                info = zf.getinfo(split_apk_file)
                info.filename = package_id+'.base.apk'
                zf.extract(info, workdir)

    if split_apk_file:
        # Delete split apk file, rename base apk file
        os.remove(file)
        os.rename(path.join(workdir, package_id+'.base.apk'), file)


def decompile_apks(force=False):
    """
    Decompile the apks using apktool
    :param force: force decompiling of apks, even if the apk file has already been decompiled before
    """

    # Find apk files in working directory
    apks = glob.glob(path.join(workdir, '*.apk'))

    if len(apks) == 0:
        print(colored('Error: no apk files found in working directory', 'red'))
        sys.exit(1)

    print(f'{len(apks)} apk files found')

    # Decompile apk files
    decompile_dir = path.join(workdir, 'decompiled')
    if not path.exists(decompile_dir):
        os.mkdir(decompile_dir)
    for apk in apks:
        print(f'Decompiling {path.basename(apk)}...')

        # Check if apk is already decompiled
        decompile_apk_dir = path.join(decompile_dir, path.splitext(path.basename(apk))[0])
        if path.exists(decompile_apk_dir):
            if force:
                # Delete directory
                print(colored(f'Deleting existing decompiled directory', 'yellow'))
                shutil.rmtree(decompile_apk_dir)
            else:
                # Skip app
                print(colored(f'Skipping decompilation of {path.basename(apk)}, already decompiled', 'yellow'))
                continue

        # Run apktool
        cmd = f'apktool d "{apk}" -o "{decompile_apk_dir}"'
        success = os.system(cmd)
        if success != 0:
            print(colored(f'Error: failed to decompile {path.basename(apk)}', 'red'))
        else:
            print(f'App decompiled to {decompile_apk_dir}')


def extract_urls(force=False):
    """
    Extract the urls from the decompiled apks
    :param force: force extraction of urls, even if the urls have already been extracted before
    """

    # Find decompiled apk files in working directory
    decompiled_dirs = [file for file in glob.glob(path.join(workdir, 'decompiled', '*')) if path.isdir(file)]

    if len(decompiled_dirs) == 0:
        print(colored('Error: no decompiled apps found in working directory', 'red'))
        sys.exit(1)

    print(f'{len(decompiled_dirs)} decompiled apps found')

    # Extract URLs from decompiled apk files
    for decompiled_dir in decompiled_dirs:
        print(f'Extracting URLs from {path.basename(decompiled_dir)}...')

        # Check if URLs have already been extracted
        json_path = path.join(decompiled_dir, 'urls.json')
        if path.exists(json_path):
            if force:
                # Delete file
                print(colored(f'Deleting existing extracted URLs file', 'yellow'))
                os.remove(json_path)

                processed_json_path = path.join(decompiled_dir, 'urls_processed.json')
                if path.exists(processed_json_path):
                    # Delete processed URL files, it depends on the urls.json file
                    os.remove(processed_json_path)

                analyzed_json_path = path.join(decompiled_dir, 'urls_analyzed.json')
                if path.exists(analyzed_json_path):
                    # Delete analyzed URL files, it depends on the urls.json file
                    os.remove(analyzed_json_path)
            else:
                # Skip app
                print(colored(f'Skipping extraction of URLs from {path.basename(decompiled_dir)}, already extracted', 'yellow'))
                continue

        # Extract URLs from app
        urls = extract_app_urls(decompiled_dir)
        print(f'{len(urls)} URLs found')

        # Write URLs to file
        with open(json_path, 'w') as f:
            json.dump(urls, f)
            print(f'URLs saved to {json_path}')


def extract_app_urls(app_dir):
    """
    Extract the urls from the decompiled apk
    :param app_dir: directory of the decompiled app files
    :return: list of objects that contain the found urls, as well as their file, line and domain name 
    """
    url_regex = re.compile('(https?://((?:www\.)?[-a-zA-Z0-9@:%._+~#=]{2,256}\.[a-z]{2,6})[-a-zA-Z0-9@:%_+.~#?&/=]*)')
    urls = []

    # Loop through all files in app directory
    for root, dirs, files in os.walk(app_dir):
        for file in files:
            if os.path.splitext(file)[1] not in ['.smali', '.xml', '.js', '.html', '.java', '.json']:
                # Do not extract URLs from text file such as README or LICENSE files or binary files
                continue

            try:
                with open(os.path.join(root, file), 'r') as f:
                    for line in f.readlines():
                        if 'http' not in line:
                            # Not a URL, save time running regex
                            continue

                        # Find all URLs in line
                        results = url_regex.findall(line)

                        if len(line) > 1024:
                            # Do not save large lines, they may be very large minified files
                            # with all contents on one line
                            line = None

                        for result in results:
                            urls.append({
                                'file': os.path.join(root, file),
                                'line': line,
                                'url': result[0],
                                'domain': result[1]
                            })
            except UnicodeDecodeError:
                # Skip binary file
                pass

    return urls


def process_urls(force=False):
    """
    Process the urls extracted from the decompiled apks by removing non-api urls
    :param force: force processing of urls, even if the urls have already been processed before
    """

    # Find extracted URLs in working directory
    json_files = [file for file in glob.glob(path.join(workdir, 'decompiled', '*', 'urls.json')) if path.isfile(file)]

    if len(json_files) == 0:
        print(colored('Error: no extracted URLs found in working directory', 'red'))
        sys.exit(1)

    print(f'{len(json_files)} apps with extracted URLs found')

    # Process extracted URL files
    for json_file in json_files:
        print(f'Processing URLs from {path.basename(path.dirname(json_file))}...')

        # Check if URLs have already been processed
        json_path = path.join(path.dirname(json_file), 'urls_processed.json')
        if path.exists(json_path):
            if force:
                # Delete file
                print(colored(f'Deleting existing processed URLs file', 'yellow'))
                os.remove(json_path)

                analyzed_json_path = path.join(path.dirname(json_file), 'urls_analyzed.json')
                if path.exists(analyzed_json_path):
                    # Delete analyzed URL files, it depends on the urls.json file
                    os.remove(analyzed_json_path)
            else:
                # Skip app
                print(colored(f'Skipping processing of URLs from {path.basename(path.dirname(json_file))}, already processed', 'yellow'))
                continue

        # Load URLs from json file
        with open(json_file, 'r') as f:
            urls = json.load(f)

        # Process URLs
        processed_urls = []
        for url in urls:
            # Check if URL is an api URL
            if url['line'] is not None and url['line'].strip()[0] in ['*', '/']:
                # Skip comments
                continue
            if 'w3.org' in url['domain'].lower() or \
                    'ns.adobe.com' in url['domain'].lower() or \
                    'xml.org' in url['domain'].lower() or \
                    'xml.apache.org' in url['domain'].lower() or \
                    'xmlpull.org' in url['domain'].lower() or \
                    'ietf.org' in url['domain'].lower() or \
                    'useplus.org' in url['domain'].lower() or \
                    'cipa.jp' in url['domain'].lower() or \
                    'whatwg.org' in url['domain'].lower() or \
                    'java.sun.com' in url['domain'].lower() or \
                    'json-schema.org' in url['domain'].lower() or \
                    'iptc.org' in url['domain'].lower() or \
                    'aiim.org' in url['domain'].lower() or \
                    'npes.org' in url['domain'].lower() or \
                    'aomedia.org' in url['domain'].lower() or \
                    'purl.org/dc/' in url['url'].lower() or \
                    'specs' in url['url'].lower() or \
                    'specification' in url['url'].lower() or \
                    'shemas' in url['url'].lower() or \
                    'schemas' in url['url'].lower() or \
                    'xsd' in url['url'].lower():
                # Skip resource schema URLs and protocols
                continue
            if 'example.' in url['domain'].lower():
                # Skip example domain
                continue
            if url['domain'].lower() == 'github.com' or \
                    url['domain'].lower() == 'bitbucket.org' or \
                    url['domain'].lower() == 'gitlab.com' or \
                    url['domain'].lower() == 'code.google.com' or \
                    url['domain'].lower() == 'jquery.org' or \
                    url['domain'].lower() == 'jsoup.org' or \
                    url['domain'].lower() == 'momentjs.com' or \
                    url['domain'].lower() == 'stackoverflow.com':
                # Skip links to code
                continue
            if url['domain'].lower() == 'goo.gl' or \
                    url['domain'].lower() == 'amzn.to' or \
                    url['domain'].lower() == 'bit.ly' or \
                    url['domain'].lower() == 'fb.gg' or \
                    url['domain'].lower() == 'fb.me' or \
                    url['domain'].lower() == 'go.microsoft.com':
                # Skip shortened URLs
                continue
            if 'license' in url['url'].lower() or \
                    'mozilla.org/mpl' in url['url'].lower():
                # Skip license URLs
                continue
            if 'docs' in url['url'].lower() or 'documentation' in url['url'].lower():
                # Skip documentation URLs
                continue
            if '.html' in url['url'].lower():
                # Skip plain HTML files
                continue
            if 'play.google.com/store' in url['url'].lower():
                # Skip Google Play store URLs
                continue
            if 'google.com/search' in url['url'].lower() or url['domain'] == 'www.google.com':
                # Skip Google search URLs
                continue
            if url['domain'] == '.facebook.com' or \
                    url['domain'] == 'facebook.com' or \
                    url['domain'] == 'www.facebook.com' or \
                    url['domain'] == 'm.facebook.com' or \
                    url['domain'] == 'plus.google.com' or \
                    url['domain'] == 'instagram.com' or \
                    url['domain'] == 'www.instagram.com' or \
                    url['domain'] == 'twitter.com' or \
                    url['domain'] == 'www.twitter.com' or \
                    url['domain'] == 'linkedin.com' or \
                    url['domain'] == 'www.linkedin.com' or \
                    url['domain'] == 'youtube.com' or \
                    url['domain'] == 'www.youtube.com':
                # Skip social media URLs that are not API endpoints
                # API endpoints use different (sub)domains than the domains above
                continue
            if any(url['url'].endswith(extension) for extension in ['.png', '.jpg', '.jpeg', '.gif', '.svg', '.webp', '.mp3', '.mp4', '.webm']):
                # Skip images / video / audio
                continue

            processed_urls.append(url)

        print(f'{len(processed_urls)} URLs processed')

        # Write URLs to json file
        with open(json_path, 'w') as f:
            json.dump(processed_urls, f)
            print(f'Processed URLs saved to {json_path}')


def analyze_urls(force=False):
    """
    Analyze the urls extracted from the decompiled apks by counting the number of unique domains, unique URLs and HTTP(S) usage
    :param force: force analysis of urls, even if the urls have already been analyzed before
    """

    # Find extracted URLs in working directory
    json_files = [file for file in glob.glob(path.join(workdir, 'decompiled', '*', 'urls_processed.json')) if path.isfile(file)]

    if len(json_files) == 0:
        print(colored('Error: no processed URLs found in working directory', 'red'))
        sys.exit(1)

    print(f'{len(json_files)} apps with processed URLs found')

    # Process extracted URL files
    for json_file in json_files:
        print(f'Analyzing URLs from {path.basename(path.dirname(json_file))}...')

        # Check if URLs have already been analyzed
        json_path = path.join(path.dirname(json_file), 'urls_analyzed.json')
        if path.exists(json_path):
            if force:
                # Delete file
                print(colored(f'Deleting existing analyzed URLs file', 'yellow'))
                os.remove(json_path)
            else:
                # Skip app
                print(colored(f'Skipping analysis of URLs from {path.basename(path.dirname(json_file))}, already analyzed', 'yellow'))
                continue

        # Load URLs
        with open(json_file, 'r') as f:
            urls = json.load(f)

        # Analyze URLs
        domain_list = set([url['domain'] for url in urls])
        domain_count = len(domain_list)

        url_list = set([(url['url'], url['domain'], url['url'].lower().startswith('https://')) for url in urls])
        url_count = len(url_list)
        url_https_count = len([url for url in url_list if url[2]])
        url_http_count = len([url for url in url_list if not url[2]])

        # Write URLs to json file
        with open(json_path, 'w') as f:
            json.dump({
                'domains': sorted(list(domain_list)),
                'domain_count': domain_count,
                'urls': [{
                    'url': url[0],
                    'domain': url[1],
                    'https': url[2]
                } for url in url_list],
                'url_count': url_count,
                'url_https_count': url_https_count,
                'url_http_count': url_http_count
            }, f, indent=4)
            print(f'Analysis info saved to {json_path}')


def analyze_tls(force=False, force_failed=False):
    """
    Analyze TLS support for the domains extracted from the apps using tls-scan
    :param force: force analysis of TLS, even if the TLS has already been analyzed before
    :param force_failed: force re-analysis of TLS for domains which tls-scan previously failed
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


def calculate_statistics():
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
    top_apps = get_top_apps(top_bottom_apps_count)
    bottom_apps = get_bottom_apps(top_bottom_apps_count)

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

    (can_use_cleartext, cannot_use_cleartext) = calculate_cleartext_traffic_usage()

    # Display statistics for HTTP/HTTPS usage in apps
    labels = ('HTTP only', 'Mixed', 'HTTPS only')
    application_count = len(urls_json_files)
    values = [http_only_apps, application_count - http_only_apps - https_only_apps, https_only_apps]
    plot_bar_chart(labels, values, 'Apps', 'HTTP/HTTPS usage in apps')

    labels = ('HTTP only', 'Mixed', 'HTTPS only')
    values = [http_only_top_apps, top_bottom_apps_count - http_only_top_apps - https_only_top_apps, https_only_top_apps]
    plot_bar_chart(labels, values, 'Apps', f'HTTP/HTTPS usage in top {top_bottom_apps_count} apps')

    labels = ('HTTP only', 'Mixed', 'HTTPS only')
    values = [http_only_bottom_apps, top_bottom_apps_count - http_only_bottom_apps - https_only_bottom_apps, https_only_bottom_apps]
    plot_bar_chart(labels, values, 'Apps', f'HTTP/HTTPS usage in bottom {top_bottom_apps_count} apps')

    # Display statistics for HTTP/HTTPS usage for domains
    labels = ('HTTP only', 'Mixed', 'HTTPS only')
    values = [len(http_only_domains), len(mixed_domains), len(https_only_domains)]
    plot_bar_chart(labels, values, 'Domains', 'HTTP/HTTPS usage for domains')

    # Display statistics for TLS configuration of domains
    labels = ('Unresolved', 'No TLS, using HTTP', 'TLS, using HTTP', 'No TLS, using Mixed', 'TLS, using Mixed', 'No TLS, using HTTPS', 'TLS, using HTTPS')
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
    labels = ('Cleartext traffic', 'No cleartext traffic')
    values = [can_use_cleartext, cannot_use_cleartext]
    plot_bar_chart(labels, values, 'Apps', 'Usage of usesCleartextTraffic flag')


def calculate_cleartext_traffic_usage():
    # Enumerate AndroidManifest.xml files of applications
    manifest_files = [file for file in glob.glob(path.join(workdir, 'decompiled', '*', 'AndroidManifest.xml')) if path.isfile(file)]

    # Statistics
    can_use_cleartext = 0
    cannot_use_cleartext = 0

    for manifest_file in manifest_files:
        with open(manifest_file, 'r') as f:
            manifest_xml = f.read()

        # Extract SDK version using regex
        sdk_version = re.search('platformBuildVersionCode="(.*?)"', manifest_xml).group(1)
        if sdk_version >= '28':
            # App should include usesCleartextTraffic to use HTTP traffic
            if 'android:usesCleartextTraffic="true"' in manifest_xml:
                can_use_cleartext += 1
            else:
                cannot_use_cleartext += 1

    return can_use_cleartext, cannot_use_cleartext


def add_bar_chart_labels(labels, values):
    # Add labels with the value of each bar
    for i in range(len(labels)):
        plt.text(i, values[i] + max(values) * 0.01, values[i], ha='center')


def plot_bar_chart(labels, values, y_label, title, rotate_labels=False):
    y_pos = np.arange(len(labels))
    fig = plt.figure(figsize=(len(labels)*2, 6))
    plt.bar(y_pos, values, align='center')
    add_bar_chart_labels(labels, values)
    if rotate_labels:
        plt.xticks(y_pos, map(uc_first, labels), rotation=-10, ha='left')
    else:
        plt.xticks(y_pos, map(uc_first, labels))
    plt.ylabel(y_label)
    plt.title(title)
    fig.tight_layout()
    plt.show()


def get_top_apps(amount=100):
    if not path.exists(path.join(workdir, 'apps.json')):
        print(colored('No apps.json file found, cannot determine top apps', 'yellow'))
        return None

    # Loop through apps to download
    with open(path.join(workdir, 'apps.json')) as f:
        packages = json.load(f)

    top_apps = []
    index = 1
    while len(top_apps) < amount:
        for package in packages:
            if package['index'] == index:
                top_apps.append(package['package_id'])
            if len(top_apps) == amount:
                break
        index += 1

    return top_apps


def get_bottom_apps(amount=100):
    if not path.exists(path.join(workdir, 'apps.json')):
        print(colored('No apps.json file found, cannot determine bottom apps', 'yellow'))
        return None

    # Loop through apps to download
    with open(path.join(workdir, 'apps.json')) as f:
        packages = json.load(f)

    bottom_apps = []
    index = max(package['index'] for package in packages)
    while len(bottom_apps) < amount:
        for package in packages:
            if package['index'] == index:
                bottom_apps.append(package['package_id'])
            if len(bottom_apps) == amount:
                break
        index -= 1

    return bottom_apps



def uc_first(string):
    return string[0].upper() + string[1:]


if __name__ == '__main__':
    run()

# TODO
# - Add graphs comparing e.g. top 100 to bottom 100
