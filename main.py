import argparse
import sys
from os import path
from termcolor import colored
import stage.scrape_package_ids
import stage.download_apks
import stage.decompile_apks
import stage.extract_urls
import stage.process_urls
import stage.analyze_urls
import stage.analyze_tls
import stage.calculate_statistics

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

    parser.add_argument('-l', '--limit_apps', nargs='?', type=int,  dest='limit_apps',
                        help='limit the number of apps to download and analyze to the given number')

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
        stage.scrape_package_ids.scrape_package_ids(workdir, args.force_scrape)

        print("\n=== Downloading apps ===")
        stage.download_apks.download_apks(workdir, args.force_download_apps, args.google_username, args.google_password, args.limit_apps)

        print("\n=== Decompiling apps ===")
        stage.decompile_apks.decompile_apks(workdir, args.force_decompile)

        print("\n=== Extracting URLs ===")
        stage.extract_urls.extract_urls(workdir, args.force_extract)

        print("\n=== Processing URLs ===")
        stage.process_urls.process_urls(workdir, args.force_process)

        print("\n=== Analyzing URLs ===")
        stage.analyze_urls.analyze_urls(workdir, args.force_analyze)

        print("\n=== Analyzing TLS configurations ===")
        stage.analyze_tls.analyze_tls(workdir, args.force_analyze_tls, args.force_analyze_tls_failed)

    print("\n=== Plotting statistics ===")
    stage.calculate_statistics.calculate_statistics(workdir)


if __name__ == '__main__':
    run()
