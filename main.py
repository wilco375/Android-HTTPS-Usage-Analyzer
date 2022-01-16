import subprocess
import sys
import os
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
        success = os.system(cmd)
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
                # Do not extract URLs from text file such as README or LICENSE files
                continue

            try:
                with open(os.path.join(root, file), 'r') as f:
                    for line in f.readlines():
                        if 'http' not in line:
                            # Not a URL, save time running regex
                            continue

                        # Find all URLs in line
                        results = url_regex.findall(line)
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
            if url['line'].strip()[0] in ['*', '/']:
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
                if domain in tls_configs and not force and not (force_failed and tls_configs[domain] is None):
                    print(colored(f'Skipping analysis of TLS of {domain}, already analyzed', 'yellow'))
                    continue
                else:
                    domains.add(domain)

    # Analyze TLS configurations
    print(f'Analyzing TLS configurations for {len(domains)} domains')

    for domain in domains:
        print(f'Analyzing TLS for {domain}...')

        # Run tls-scan on the domain
        retry = 3
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
    http_only_apps = 0
    https_only_apps = 0

    http_urls = 0
    https_urls = 0

    http_with_https_available = 0
    https_with_old_config = 0
    https_with_intermediate_config = 0
    https_with_modern_config = 0

    urls_json_files = [file for file in glob.glob(path.join(workdir, 'decompiled', '*', 'urls_analyzed.json')) if path.isfile(file)]
    tls_json_file = path.join(workdir, 'tls.json')
    with open(tls_json_file, 'r') as f:
        tls_data = json.load(f)

    application_count = len(urls_json_files)

    for urls_json_file in urls_json_files:
        with open(urls_json_file, 'r') as f:
            data = json.load(f)
        if data['url_https_count'] == 0 and data['url_http_count'] != 0:
            http_only_apps += 1
        elif data['url_https_count'] != 0 and data['url_http_count'] == 0:
            https_only_apps += 1

        http_urls += data['url_http_count']
        https_urls += data['url_https_count']

        for url in data['urls']:
            if not url['https']:
                # Check if URL supports TLS
                if tls_data[url['domain']] is None:
                    # Not a valid domain
                    http_urls -= 1
                elif tls_data[url['domain']] is not False:
                    # URL domain has TLS support
                    http_with_https_available += 1
            else:
                # Check if TLS is secure
                if tls_data[url['domain']] is None:
                    # Not a valid domain
                    https_urls -= 1
                elif tls_data[url['domain']] is False:
                    # URL domain does not have TLS support
                    https_with_old_config += 1
                else:
                    security = mozilla_tls_configuration_security(tls_data[url['domain']])
                    if security == 'old':
                        https_with_old_config += 1
                    elif security == 'intermediate':
                        https_with_intermediate_config += 1
                    elif security == 'modern':
                        https_with_modern_config += 1

    print(f"Found {http_only_apps}/{application_count} applications with HTTP only")
    print(f"Found {https_only_apps}/{application_count} applications with HTTPS only")
    print(f"Found {application_count - http_only_apps - https_only_apps}/{application_count} applications with mixed HTTP/HTTPS")

    print(f"Found {http_with_https_available}/{http_urls} URLs using HTTP that could also use HTTPS")
    print(f"Found {https_with_old_config}/{https_urls} URLs using old TLS config")
    print(f"Found {https_with_intermediate_config}/{https_urls} URLs using intermediate TLS config")
    print(f"Found {https_with_modern_config}/{https_urls} URLs using modern TLS config")


def mozilla_tls_configuration_security(configuration):
    # The TLS version reported in tlsVersion does not always seem to be in the tlsVersions list
    if configuration['tlsVersion'] not in configuration['tlsVersions']:
        configuration['tlsVersions'].append(configuration['tlsVersion'].replace('.', '_'))

    # TODO Add cipher checks
    if 'TLSv1_3' in configuration['tlsVersions']:
        if len(configuration['tlsVersions']) == 1:
            # Supports only TLS 1.3
            return 'modern'
        elif 'TLSv1_2' in configuration['tlsVersions'] and \
                len(configuration['tlsVersions']) == 2:
            # Supports only TLS 1.2 and TLS 1.3
            return 'intermediate'
        else:
            return 'old'


if __name__ == '__main__':
    run()
