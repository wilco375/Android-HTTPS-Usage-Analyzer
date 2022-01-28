import glob
import os
import shutil
from os import path
from termcolor import colored


def decompile_apks(workdir, force=False):
    """
    Decompile the apks using apktool
    :param workdir: working directory
    :type workdir: str
    :param force: force decompiling of apks, even if the apk file has already been decompiled before
    :type force: bool
    """
    # Get apks
    apks = _get_apks(workdir)
    if len(apks) == 0:
        return

    # Decompile apks
    decompile_dir = path.join(workdir, 'decompiled')
    if not path.exists(decompile_dir):
        os.mkdir(decompile_dir)

    for apk in apks:
        _decompile_apk(decompile_dir, apk, force)


def _get_apks(workdir):
    """
    Get a list of all apks in the working directory
    :return: list of apks
    :rtype: list[str]
    """
    # Find apk files in working directory
    apks = glob.glob(path.join(workdir, '*.apk'))

    if len(apks) == 0:
        print(colored('Error: no apk files found in working directory', 'red'))
        return []

    print(f'{len(apks)} apk files found')
    return apks


def _decompile_apk(decompile_dir, apk, force=False):
    """
    Decompile apk
    :param decompile_dir: directory to decompile apks to
    :type decompile_dir: str
    :param apk: apk file to decompile
    :type apk: str
    :param force: if True, force decompiling of apk even if the apk has already been decompiled before
    :type force: bool
    """
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
            return

    # Run apktool
    cmd = f'apktool d "{apk}" -o "{decompile_apk_dir}"'
    success = os.system(cmd)
    if success != 0:
        print(colored(f'Error: failed to decompile {path.basename(apk)}', 'red'))
    else:
        print(f'App decompiled to {decompile_apk_dir}')
