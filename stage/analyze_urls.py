import glob
import json
import os
from os import path
from termcolor import colored


def analyze_urls(workdir, force=False):
    """
    Analyze the urls extracted from the decompiled apks by counting the number of unique domains, unique URLs and HTTP(S) usage
    :param workdir: the working directory
    :type workdir: str
    :param force: force analysis of urls, even if the urls have already been analyzed before
    :type force: bool
    """
    # Find extracted URLs in working directory
    json_files = [file for file in glob.glob(path.join(workdir, 'decompiled', '*', 'urls_processed.json')) if
                  path.isfile(file)]

    if len(json_files) == 0:
        print(colored('Error: no processed URLs found in working directory', 'red'))
        return

    print(f'{len(json_files)} apps with processed URLs found')

    # Process extracted URL files
    for json_file in json_files:
        print(f'Analyzing URLs from {path.basename(path.dirname(json_file))}...')

        # Check if URLs have already been analyzed
        if _check_existing_json_file(json_file, force):
            continue

        # Analyze URLs
        analyzed_urls = _analyze_urls(json_file)

        # Write URLs to json file
        _save_to_json_file(json_file, analyzed_urls)


def _check_existing_json_file(json_file, overwrite=False):
    """
    Check for an existing JSON file of extracted URLs
    :param json_file: URLs JSON file
    :type json_file: str
    :param overwrite: will delete the current JSON file if one exists
    :type overwrite: bool
    :return: True if JSON file exists and is not overwritten, False otherwise
    :rtype: bool
    """
    json_path = path.join(path.dirname(json_file), 'urls_analyzed.json')
    if path.exists(json_path):
        if overwrite:
            # Delete file
            print(colored(f'Deleting existing analyzed URLs file', 'yellow'))
            os.remove(json_path)
            return False
        else:
            # Skip app
            print(colored(
                f'Skipping analysis of URLs from {path.basename(path.dirname(json_file))}, already analyzed',
                'yellow'))
            return True


def _analyze_urls(json_file):
    """
    Analyze the found URLs
    :param json_file: JSON file containing extracted URLs
    :type json_file: str
    :return: analyzed data
    :rtype: dict
    """
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

    return {
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
    }


def _save_to_json_file(json_file, analyzed_urls):
    """
    Save the list of apps to a JSON file
    :param json_file: URLs JSON file
    :type json_file: str
    :param analyzed_urls: list of analyzed urls
    :type analyzed_urls: list[dict
    """
    json_path = path.join(path.dirname(json_file), 'urls_analyzed.json')
    with open(json_path, 'w') as f:
        json.dump(analyzed_urls, f, indent=4)
        print(f'Analysis info saved to {json_path}')
