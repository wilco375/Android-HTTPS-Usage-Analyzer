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
    package_ids = [package['package_id'] for package in packages if package['index'] <= 3]
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
    url_regex = re.compile('(.*(https?://((?:www\.)?[-a-zA-Z0-9@:%._+~#=]{2,256}\.[a-z]{2,6})[-a-zA-Z0-9@:%_+.~#?&/=]*).*)')
    urls = []

    # Loop through all files in app directory
    for root, dirs, files in os.walk(app_dir):
        for file in files:
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
                                'line': result[0],
                                'url': result[1],
                                'domain': result[2]
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
            if 'schemas.android.com' in url['domain'].lower() or 'w3.org' in url['domain'].lower() or 'xsd' in url['url']:
                # Skip resource schema URLs
                continue
            if 'example.' in url['domain'].lower():
                # Skip example domain
                continue
            if url['domain'].lower() == 'github.com':
                # Skip links to GitHub repositories
                continue
            if 'license' in url['url'].lower():
                # Skip license URLs
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

        url_list = set([url['url'] for url in urls])
        url_count = len(url_list)
        url_https_count = len([url for url in url_list if url.lower().startswith('https://')])
        url_http_count = len([url for url in url_list if url.lower().startswith('http://')])

        # Write URLs to json file
        with open(json_path, 'w') as f:
            json.dump({
                'domains': list(domain_list),
                'domain_count': domain_count,
                'urls': list(url_list),
                'url_count': url_count,
                'url_https_count': url_https_count,
                'url_http_count': url_http_count
            }, f, indent=4)
            print(f'Analysis info saved to {json_path}')


if __name__ == '__main__':
    run()
