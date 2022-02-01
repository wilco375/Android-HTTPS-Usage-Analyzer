import glob
import json
import os
import time
import zipfile
from os import path

import toolz
from termcolor import colored


def download_apks(workdir, force=False, google_username=None, google_password=None, limit=None):
    """
    Download the apks for the top apps using apkeep
    :param workdir: Working directory
    :type workdir: str
    :param force: force downloading of apks, even if apk file already exists
    :type force: bool
    :param google_username: Google username to use with apkeep to download apks from the Google Play store
    :type google_username: str|None
    :param google_password: Google password to use with apkeep to download apks from the Google Play store
    :type google_password: str|None
    :param limit: Limit the number of apps to download
    :type limit: int|None
    """
    # Check if JSON file with apps to download exists
    if not path.exists(path.join(workdir, 'apps.json')):
        print(colored('No apps.json file found, not downloading any apks', 'yellow'))
        return

    # Download scraped apps
    package_ids = _get_package_ids(workdir)
    existing_apks = glob.glob(path.join(workdir, '*.apk'))
    if not force and len(existing_apks) >= limit:
        print(colored('Limit of apps to download reached with already downloaded apps, skipping downloading', 'yellow'))
        return

    success_count = len(existing_apks)
    for package_id in package_ids:
        success = _download_apk(workdir, package_id, force, google_username, google_password)

        # Check if limit of apps to download has been reached
        if success:
            success_count += 1
        if limit is not None and success_count >= limit:
            break


def _get_package_ids(workdir):
    """
    Get a list of package ids scraped from the Google Play Store
    :param workdir: Working directory
    :type workdir: str
    :return: list of package ids
    :rtype: list[str]
    """
    with open(path.join(workdir, 'apps.json')) as f:
        packages = json.load(f)
    packages = toolz.sorted(packages, key=lambda package: package['index'])
    return [package['package_id'] for package in packages]


def _download_apk(workdir, package_id, force=False, google_username=None, google_password=None):
    """
    Download the apk of the given package using apkeep
    Will download the app from the Google Play Store if a Google username and password are provided,
    or from APKPure if no login is provided
    :param workdir: Working directory
    :param package_id: Package ID of app to download
    :param force: if True, overwrite the app if it is already downloaded
    :param google_username: Google username to download the app from the Google Play Store
    :param google_password: Google password to download the app from the Google Play Store
    :return: True if downloaded successfully, False otherwise
    :rtype: bool
    """
    apk_file = path.join(workdir, package_id + '.apk')

    # Check if apk file already exists
    if path.exists(apk_file):
        if force:
            # Delete file
            print(colored(f'Deleting existing apk file', 'yellow'))
            os.remove(apk_file)
        else:
            # Skip app
            print(colored(f'Skipping download of {package_id}, already exists', 'yellow'))
            return

    # Download apk file using apkeep
    cmd = f'apkeep -a "{package_id}" "{workdir}"'
    if google_username and google_password:
        # Download from the Google Play Store if username and password are provided
        cmd += f' -d GooglePlay -u "{google_username}" -p "{google_password}"'

    retry = 0
    success = 1
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
        return False
    else:
        print(f'App downloaded to {workdir}')
        return _validate_apk(workdir, package_id, apk_file)


def _validate_apk(workdir, package_id, file):
    """
    Check if the apk file is valid. If it is a split apk, extract the core apk. If invalid, delete the file
    :param workdir: Working directory
    :type workdir: str
    :param package_id: package id of the app
    :type package_id: str
    :param file: path of apk file to check
    :type file: str
    :return: True if valid, False otherwise
    :rtype: bool
    """
    # Check if apk file exists
    if not path.exists(file):
        print(colored(f'Error: app {package_id} failed to download', 'red'))
        return False

    # Check if apk file is a zip file
    if not zipfile.is_zipfile(file):
        print(colored(f'Error: {file} is not a valid apk file, deleting file', 'red'))
        os.remove(file)
        return False

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

    return True
