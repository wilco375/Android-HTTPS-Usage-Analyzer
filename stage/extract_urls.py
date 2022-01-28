import glob
import json
import os
import re
from os import path
from termcolor import colored


def extract_urls(workdir, force=False):
    """
    Extract the urls from the decompiled apks
    :param workdir: working directory
    :type workdir: str
    :param force: force extraction of urls, even if the urls have already been extracted before
    :type force: bool
    """
    # Get list of decompiled app directories
    decompiled_dirs = _get_decompiled_dirs(workdir)
    if len(decompiled_dirs) == 0:
        return

    # Extract URLs from decompiled apk files
    for decompiled_dir in decompiled_dirs:
        print(f'Extracting URLs from {path.basename(decompiled_dir)}...')

        # Check if URLs have already been extracted
        _check_existing_json_file(decompiled_dir, force)

        # Extract URLs from app
        urls = _extract_app_urls(decompiled_dir)

        # Write URLs to file
        _save_to_json_file(decompiled_dir, urls)


def _get_decompiled_dirs(workdir):
    """
    # Find directories of decompiled apk files in working directory
    :param workdir: working directory
    :type workdir: str
    :return: list of directories of decompiled apks
    :rtype: list[str]
    """
    decompiled_dirs = [file for file in glob.glob(path.join(workdir, 'decompiled', '*')) if path.isdir(file)]

    if len(decompiled_dirs) == 0:
        print(colored('Error: no decompiled apps found in working directory', 'red'))
    else:
        print(f'{len(decompiled_dirs)} decompiled apps found')

    return decompiled_dirs


def _check_existing_json_file(decompiled_dir, overwrite=False):
    """
    Check for an existing JSON file of extracted URLs
    :param decompiled_dir: decompiled app directory
    :type decompiled_dir: str
    :param overwrite: will delete the current JSON file if one exists
    :type overwrite: bool
    :return: True if JSON file exists and is not overwritten, False otherwise
    :rtype: bool
    """
    json_path = path.join(decompiled_dir, 'urls.json')
    if path.exists(json_path):
        if overwrite:
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
            return True


def _extract_app_urls(app_dir):
    """
    Extract the urls from the decompiled apk
    :param app_dir: directory of the decompiled app files
    :type app_dir: str
    :return: list of objects that contain the found urls, as well as their file, line and domain name
    :rtype: list[dict]
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

    print(f'{len(urls)} URLs found')

    return urls


def _save_to_json_file(decompiled_dir, urls):
    """
    Save the list of apps to a JSON file
    :param decompiled_dir: decompiled app directory
    :type decompiled_dir: str
    :param urls: list of urls
    :type urls: list[dict]
    """
    json_path = path.join(decompiled_dir, 'urls.json')
    with open(json_path, 'w') as f:
        json.dump(urls, f)
        print(f'URLs saved to {json_path}')