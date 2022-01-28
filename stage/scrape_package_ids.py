import os
from os import path
import toolz
from termcolor import colored
import requests
import re
from bs4 import BeautifulSoup
import json


def scrape_package_ids(workdir, force=False):
    """
    Scrape the Google Play Store for the top apps of each category and save their package ids to a JSON file
    :param workdir: Working directory
    :type workdir: str
    :param force: force extraction of package ids, even if json file already exists
    :type force: bool
    """

    # Check JSON file
    if _check_existing_json_file(workdir, force):
        return

    # Scrape categories
    category_urls = _scrape_categories()
    if len(category_urls) == 0:
        return

    # Scrape apps
    apps = []
    for category_url in category_urls:
        category_apps = _scrape_category(category_url)
        if category_apps is not None:
            apps.extend(category_apps)

    # Remove potential duplicates
    apps = toolz.unique(apps, key=lambda app: app['package_id'])

    # Save apps to JSON file
    _save_to_json_file(workdir, apps)


def _check_existing_json_file(workdir, overwrite=False):
    """
    Check for an existing JSON file containing scraped package IDs
    :param workdir: Working directory
    :type workdir: str
    :param overwrite: will delete the current JSON file if one exists
    :type overwrite: bool
    :return: True if JSON file exists and is not overwritten, False otherwise
    :rtype: bool
    """
    apps_json = path.join(workdir, 'apps.json')
    if path.exists(apps_json):
        if overwrite:
            # Delete file
            print(colored(f'Deleting existing apk file', 'yellow'))
            os.remove(apps_json)
        else:
            # Skip package id scraping
            print(colored(f'Skipping extracting of package ids from Google Play, already extracted', 'yellow'))
            return True
    return False


def _scrape_categories():
    """
    Scrape the Google Play Store home page for a list of categories
    :return: list of category URLs
    :rtype: list[string]
    """
    url = 'https://play.google.com/store/apps'
    response = requests.get(url)

    if not response.ok:
        print(colored('Error: could not retrieve list of categories from Google Play', 'red'))
        return []

    # Extract category URLs using a regex
    categories = re.findall('/store/apps/category/[A-Za-z_]+', response.text)

    # Do not include game subcategories because of large package sizes
    return [category for category in categories if 'GAME_' not in category]


def _scrape_category(category_url):
    """
    Scrape the Google Play Store category page for top apps
    :param category_url: URL of the category to scrape
    :type category_url: str
    :return: list of apps with their index in the category, package id and category
    :rtype: list[dict]
    """
    category = category_url[len('/store/apps/category/'):]
    print(f"Extracting package ids from category {category}")

    # Find the section in the category that has the top apps
    url = f'https://play.google.com{category_url}'
    response = requests.get(url)
    html = BeautifulSoup(response.text, 'html.parser')
    top_apps = html.find(text="Recommended for you")
    if top_apps is None:
        print(colored(f'Warning: could not find top apps section in category {category}', 'yellow'))
        return None

    # Extract the package ids from the top apps section
    url = 'https://play.google.com' + top_apps.find_parent('a').attrs['href']
    response = requests.get(url)
    app_ids = re.findall('(?:"/store/apps/details\?id=)([^"]+)(?:")', response.text)
    index = 1
    apps = []
    for app_id in app_ids:
        apps.append({
            'index': index,
            'package_id': app_id,
            'category': category
        })
        index += 1

    return apps


def _save_to_json_file(workdir, apps):
    """
    Save the list of apps to a JSON file
    :param workdir: Working directory
    :type workdir: str
    :param apps: list of apps
    :type apps: list[dict]
    """
    apps_json = path.join(workdir, 'apps.json')
    with open(apps_json, 'w') as f:
        print(f'Package ids saved to {apps_json}')
        json.dump(apps, f)
