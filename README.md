# Cloud Networking Project - HTTP(S) usage in Android apps
The Python script in this repository downloads the top apps from the Google Play Store, decompiles them, extracts used URLs, and analyzes the TLS configurations of the domains of these URLs. Finally, statistics are shown on HTTP(S) and TLS usage and configuration in the apps.

## Install dependencies
### Install Python dependencies
`pip3 install --requirement requirements.txt`

### Install apkeep to automatically download apk files
[Install apkeep](https://github.com/EFForg/apkeep)

### Install apktool to decompile apk files
[Install Apktool](https://ibotpeaches.github.io/Apktool/)

### Install tls-scan to analyze the TLS configurations of domains
[Install tls-scan](https://github.com/prbinu/tls-scan)

## Usage
Create a working directory to store the apk files and the output files. Then run the following command:

`python3 main.py WORKING_DIR`

For all possible options, run the following command:

`python3 main.py --help`
