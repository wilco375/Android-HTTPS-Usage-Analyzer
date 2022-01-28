import glob
import json
import os
from os import path
from termcolor import colored


def process_urls(workdir, force=False):
    """
    Process the urls extracted from the decompiled apks by removing non-api urls
    :param workdir: the working directory
    :type workdir: str
    :param force: force processing of urls, even if the urls have already been processed before
    :type force: bool
    """
    # Find extracted URLs in working directory
    json_files = [file for file in glob.glob(path.join(workdir, 'decompiled', '*', 'urls.json')) if path.isfile(file)]

    if len(json_files) == 0:
        print(colored('Error: no extracted URLs found in working directory', 'red'))
        return

    blacklist = _get_blacklist()

    print(f'{len(json_files)} apps with extracted URLs found')

    # Process extracted URL files
    for json_file in json_files:
        print(f'Processing URLs from {path.basename(path.dirname(json_file))}...')

        # Check if URLs have already been processed
        if _check_existing_json_file(json_file, force):
            continue

        # Load URLs from json file
        with open(json_file, 'r') as f:
            urls = json.load(f)

        # Process URLs
        processed_urls = []
        for url in urls:
            # Check if URL is an api URL using blacklist
            if (url['line'] is not None and any(url['line'].strip().startswith(prefix) for prefix in blacklist['lines'])) or \
                    any(in_url in url['url'].lower() for in_url in blacklist['in_urls']) or \
                    any(in_domain in url['domain'].lower() for in_domain in blacklist['in_domains']) or \
                    any(domain == url['domain'].lower() for domain in blacklist['in_domains']) or \
                    any(url['url'].lower().endswith(extension) for extension in blacklist['extensions']):
                continue

            processed_urls.append(url)

        print(f'{len(processed_urls)} URLs processed')

        # Write URLs to json file
        _save_to_json_file(path.dirname(json_file), processed_urls)


def _check_existing_json_file(json_file, overwrite=False):
    """
    Check for an existing JSON file of extracted URLs
    :param json_file: URLs json file
    :type json_file: str
    :param overwrite: will delete the current JSON file if one exists
    :type overwrite: bool
    :return: True if JSON file exists and is not overwritten, False otherwise
    :rtype: bool
    """
    json_path = path.join(path.dirname(json_file), 'urls_processed.json')
    if path.exists(json_path):
        if overwrite:
            # Delete file
            print(colored(f'Deleting existing processed URLs file', 'yellow'))
            os.remove(json_path)

            analyzed_json_path = path.join(path.dirname(json_file), 'urls_analyzed.json')
            if path.exists(analyzed_json_path):
                # Delete analyzed URL files, it depends on the urls.json file
                os.remove(analyzed_json_path)
        else:
            # Skip app
            print(colored(
                f'Skipping processing of URLs from {path.basename(path.dirname(json_file))}, already processed',
                'yellow'))
            return True
    return False


def _get_blacklist():
    """
    Get a list of blacklisted URL properties for when an URL should be discarded as a non-API URL
    :return: list of blacklisted URL properties
    :rtype: dict
    """
    blacklist = {
        'lines': [],  # URL is blacklisted if first character of line maches any of these
        'in_urls': [],  # URL is blacklisted if it contains any of these
        'in_domains': [],  # URL is blacklisted if it's domain contains any of these
        'domains': [],  # URL is blacklisted if it's domain matches any of these
        'extensions': []  # URL is blacklisted if it's extension matches any of these
    }

    # Skip comments, lines starting with / or *
    blacklist['lines'].extend(['/', '*'])

    # Skip resource schema URLs and protocols
    blacklist['in_domains'].extend(['w3.org', 'ns.adobe.com', 'xml.org', 'xml.apache.org', 'xmlpull.org',
                                    'ietf.org', 'useplus.org', 'cipa.jp', 'whatwg.org', 'java.sun.com',
                                    'json-schema.org', 'iptc.org','aiim.org', 'npes.org', 'aomedia.org'])
    blacklist['in_urls'].extend(['purl.org/dc/', 'purl.org/dc/', 'specs', 'specification', 'shemas', 'schemas', 'xsd'])

    # Skip example domain
    blacklist['in_domains'].append('example.')

    # Skip links to code
    blacklist['domains'].extend(['github.com', 'bitbucket.org', 'gitlab.com', 'code.google.com', 'jquery.org',
                                 'jsoup.org', 'momentjs.com', 'stackoverflow.com'])

    # Skip shortened URLs
    blacklist['domains'].extend(['goo.gl', 'amzn.to', 'bit.ly', 'fb.gg', 'fb.me', 'go.microsoft.com'])

    # Skip license URLs
    blacklist['in_urls'].extend(['license', 'mozilla.org/mpl'])

    # Skip documentation URLs
    blacklist['in_urls'].extend(['docs', 'documentation'])

    # Skip plain HTML files
    blacklist['extensions'].append('.html')

    # Skip Google Play Store URLs
    blacklist['in_urls'].append('play.google.com/store')

    # Skip Google search URLs
    blacklist['in_urls'].append('google.com/search')
    blacklist['domains'].append('www.google.com')

    # Skip social media URLs that are not API endpoints
    # API endpoints use different (sub)domains than the domains below
    blacklist['domains'].extend(['.facebook.com', 'facebook.com', 'www.facebook.com', 'm.facebook.com', 'plus.google.com',
                                 'instagram.com', 'www.instagram.com', 'twitter.com', 'www.twitter.com', 'linkedin.com',
                                 'www.linkedin.com', 'youtube.com', 'www.youtube.com'])

    # Skip images / video / audio
    blacklist['extensions'].extend(['.png', '.jpg', '.jpeg', '.gif', '.svg', '.webp', '.mp3', '.mp4', '.webm'])

    return blacklist


def _save_to_json_file(directory, processed_urls):
    """
    Save the list of apps to a JSON file
    :param directory: directory to write JSON to
    :type directory: str
    :param processed_urls: list of processed urls
    :type processed_urls: list[dict
    """
    json_path = path.join(directory, 'urls_processed.json')
    with open(json_path, 'w') as f:
        json.dump(processed_urls, f)
        print(f'Processed URLs saved to {json_path}')
