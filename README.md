# see-ess-pee

see-ess-pee is a tool developed by Geeknik's Lab for analyzing Content Security Policy (CSP) and Cross-Origin Resource Sharing (CORS) configurations. It helps identify potential vulnerabilities and provides recommendations for improving web security.

## Features

- Analyzes CSP headers for common vulnerabilities.
- Checks CORS configurations for potential security issues.
- Generates Proof of Concept (POC) HTML files for identified vulnerabilities.
- Provides detailed reports with severity ratings and remediation steps.

## Installation

To install see-ess-pee, clone the repository and install the required dependencies:

```bash
git clone https://github.com/geeknik/see-ess-pee/
cd see-ess-pee
pip install -r requirements.txt
```

## Usage

You can run see-ess-pee using the command line. Here are some examples:

Analyze a list of URLs:

```bash
python main.py -u https://example.com https://hackerone.com https://bugcrowd.com
```

![CleanShot 2024-10-09 at 16 30 06@2x](https://github.com/user-attachments/assets/88e9250f-0ef7-41cd-b2f2-95d9e10688cd)


Analyze URLs from a file:

```bash
python main.py -f urls.txt
```

Specify the number of worker threads and output format:

```bash
python main.py -u https://example.com -w 10 -o json
```

## License

This project is licensed under the GNU General Public License v3.0. See the [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please fork the repository and submit a pull request with your changes.

## Contact

For questions or feedback, please contact Geeknik's Lab on [X](https://x.com/geeknik).
