import glob
import json
import re
from os import path
from termcolor import colored


def get_cleartext_traffic_usage(workdir):
    """
    Calculate the number of applications with Android SDK version >= 28
    that have android:usesCleartextTraffic="true" set to true
    :param workdir: working directory
    :type workdir: str
    :return: tuple of the apps with SDK version >= 28 that respectively
    do and don't have the usesCleartextTraffic flag set to true
    :rtype: tuple[int, int]
    """
    # Enumerate AndroidManifest.xml files of applications
    manifest_files = [file for file in glob.glob(path.join(workdir, 'decompiled', '*', 'AndroidManifest.xml')) if path.isfile(file)]

    # Statistics
    can_use_cleartext = 0
    cannot_use_cleartext = 0

    # Loop through application manifest files
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


def get_top_apps(workdir, amount=100):
    """
    Get the top apps by position in Google Play Store categories
    :param workdir: working directory
    :type workdir: str
    :param amount: number of top apps to get
    :type amount: int
    :return: package ids of top apps
    :rtype: list[str]
    """
    packages = _get_apps_from_json_file(workdir)

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


def get_bottom_apps(workdir, amount=100):
    """
    Get the bottom apps by position in Google Play Store categories
    :param workdir: working directory
    :type workdir: str
    :param amount: number of bottom apps to get
    :type amount: int
    :return: package ids of bottom apps
    :rtype: list[str]
    """
    packages = _get_apps_from_json_file(workdir)

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


def _get_apps_from_json_file(workdir):
    """
    Read the scraped apps from the apps.json file
    :param workdir: working directory
    :type workdir: str
    :return: apps
    :rtype: list[dict]
    """
    if not path.exists(path.join(workdir, 'apps.json')):
        print(colored('No apps.json file found, cannot determine bottom apps', 'yellow'))
        return None

    # Loop through apps to download
    with open(path.join(workdir, 'apps.json')) as f:
        packages = json.load(f)

    return packages
