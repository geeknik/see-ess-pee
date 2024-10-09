import requests
import numpy as np
from urllib.parse import urlparse
import argparse
import concurrent.futures
import sys
import json
from datetime import datetime
import logging
from collections import defaultdict
import time
import random
import re
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn
from rich.syntax import Syntax
from rich.tree import Tree
from rich import box
from rich.layout import Layout
from rich.live import Live
from rich.text import Text

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

console = Console()

USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.77 Safari/537.36'
]

def get_random_user_agent():
    return random.choice(USER_AGENTS)

def check_cors(url, verify_ssl=True):
    origins_to_test = [
        "https://evil.com",
        "null",
        "https://localhost",
        f"https://{urlparse(url).netloc}.evil.com",
        f"https://{urlparse(url).netloc}_evil.com",
        f"https://{urlparse(url).netloc}{{evil.com",
        f"https://evil{urlparse(url).netloc}"
    ]

    vulnerabilities = []

    for origin in origins_to_test:
        try:
            headers = {
                'User-Agent': get_random_user_agent(),
                'Origin': origin
            }
            response = requests.get(url, headers=headers, verify=verify_ssl, allow_redirects=True, timeout=10)
            acao = response.headers.get('Access-Control-Allow-Origin')
            acac = response.headers.get('Access-Control-Allow-Credentials')

            if acao:
                if acao == '*' and acac == 'true':
                    vulnerabilities.append(f"Wildcard CORS with credentials: {origin}")
                elif acao == origin:
                    if acac == 'true':
                        vulnerabilities.append(f"Reflected origin with credentials: {origin}")
                    else:
                        vulnerabilities.append(f"Reflected origin without credentials: {origin}")
                elif acao and origin.endswith(acao) and acac == 'true':
                    vulnerabilities.append(f"Subdomain CORS bypass: {origin}")
                elif acao == 'null':
                    vulnerabilities.append(f"Null origin accepted: {origin}")
                    vulnerabilities.append(f"Subdomain CORS bypass: {origin}")
                elif acao == 'null':
                    vulnerabilities.append(f"Null origin accepted: {origin}")
        except requests.RequestException as e:
            logger.error(f"Error checking CORS for {url} with origin {origin}: {e}")

    return vulnerabilities

def get_csp_header(url, verify_ssl=True):
    try:
        headers = {'User-Agent': get_random_user_agent()}
        response = requests.get(url, timeout=10, headers=headers, verify=verify_ssl, allow_redirects=True)
        csp_header = response.headers.get('Content-Security-Policy')
        csp_report_only = response.headers.get('Content-Security-Policy-Report-Only')

        if csp_header:
            logger.info(f"CSP header found for {url}")
            return csp_header, False
        elif csp_report_only:
            logger.info(f"CSP Report-Only header found for {url}")
            return csp_report_only, True
        else:
            logger.warning(f"No CSP header found for {url}")
            return None, False
    except requests.exceptions.RequestException as e:
        logger.error(f"Failed to fetch {url}: {e}")
        return None, False

def parse_csp(csp_header):
    directives = {}
    for policy in csp_header.split(';'):
        parts = policy.strip().split()
        if parts:
            directive = parts[0]
            values = parts[1:] if len(parts) > 1 else []
            directives[directive] = values
    return directives

def get_severity(vulnerability):
    high_severity = ["unsafe-inline", "unsafe-eval", "Reflected origin with credentials", "Wildcard CORS with credentials"]
    medium_severity = ["Subdomain CORS bypass", "Reflected origin without credentials"]
    return "Critical" if any(v in vulnerability for v in high_severity) else "High" if any(v in vulnerability for v in medium_severity) else "Medium"

def get_recommendation(vulnerability):
    recommendations = {
        "unsafe-inline": (
            "Remove 'unsafe-inline' from your CSP. Use nonces or hashes to allow specific inline scripts and styles. "
            "This will prevent attackers from injecting malicious scripts into your web pages."
        ),
        "unsafe-eval": (
            "Eliminate 'unsafe-eval' from your CSP. Refactor your code to avoid using eval() and similar functions. "
            "Consider using safer alternatives like JSON.parse or the Function constructor."
        ),
        "Reflected origin with credentials": (
            "Implement strict origin validation by checking the Origin header against a whitelist of allowed origins. "
            "Do not reflect user-supplied origins to prevent unauthorized access and data leakage."
        ),
        "Wildcard CORS with credentials": (
            "Replace the wildcard '*' in Access-Control-Allow-Origin with specific, trusted origins. "
            "This will prevent unauthorized domains from accessing sensitive data with credentials."
        ),
        "Subdomain CORS bypass": (
            "Avoid using wildcards in Access-Control-Allow-Origin. Validate the origin against a strict list of allowed subdomains. "
            "This will prevent attackers from using subdomains to bypass CORS restrictions."
        ),
        "Reflected origin without credentials": (
            "Ensure that only trusted origins can access the resource by implementing strict origin validation. "
            "This will help prevent information leakage to untrusted origins."
        ),
        "Missing script-src directive": (
            "Add a 'script-src' directive to your CSP to specify trusted sources for scripts. "
            "This will help prevent the execution of malicious scripts on your site."
        ),
        "Missing object-src directive": (
            "Add an 'object-src' directive to your CSP to specify trusted sources for plugins and objects. "
            "This will help prevent the loading of potentially harmful plugins."
        ),
        "Missing base-uri directive": (
            "Add a 'base-uri' directive to your CSP to restrict the URLs that can be used as a base for relative URLs. "
            "This will help prevent attackers from manipulating the base URL to execute malicious scripts."
        ),
        "Missing form-action directive": (
            "Add a 'form-action' directive to your CSP to restrict the URLs that can be used as form action targets. "
            "This will help prevent attackers from redirecting form submissions to malicious sites."
        ),
        "Missing frame-ancestors directive": (
            "Add a 'frame-ancestors' directive to your CSP to control which sites can embed your content in frames. "
            "This will help prevent clickjacking attacks."
        ),
        "No nonce or strict-dynamic used": (
            "Use nonces or the 'strict-dynamic' keyword in your CSP to allow only trusted scripts to execute. "
            "This will help prevent the execution of unauthorized scripts."
        )
    }
    return next((rec for key, rec in recommendations.items() if key in vulnerability), "Review and tighten the CSP/CORS policy.")

def analyze_csp(csp_header):
    vulnerabilities = []
    directives = parse_csp(csp_header)

    if 'script-src' not in directives:
        vulnerabilities.append("Missing script-src directive")

    script_src = directives.get('script-src', directives.get('default-src', []))

    if "'unsafe-inline'" in script_src:
        vulnerabilities.append("unsafe-inline allowed in script-src")

    if "'unsafe-eval'" in script_src:
        vulnerabilities.append("unsafe-eval allowed in script-src")

    if any(src.startswith('http:') for src in script_src):
        vulnerabilities.append("HTTP sources allowed in script-src")

    if 'https:' in script_src or '*' in script_src:
        vulnerabilities.append("Overly permissive script-src")

    if 'object-src' not in directives and 'default-src' not in directives:
        vulnerabilities.append("Missing object-src directive")

    if 'base-uri' not in directives:
        vulnerabilities.append("Missing base-uri directive")

    if 'form-action' not in directives:
        vulnerabilities.append("Missing form-action directive")

    if 'frame-ancestors' not in directives:
        vulnerabilities.append("Missing frame-ancestors directive")

    nonce_pattern = r"'nonce-[a-zA-Z0-9+/=]+'"
    if not any(re.match(nonce_pattern, src) for src in script_src) and "'strict-dynamic'" not in script_src:
        vulnerabilities.append("No nonce or strict-dynamic used")

    return vulnerabilities, directives

def detect_anomalies(data):
    """Detect anomalies using Z-score method."""
    anomalies = []
    threshold = 3  # Z-score threshold for anomaly detection
    mean = np.mean(data)
    std_dev = np.std(data)

    if std_dev != 0:
        for index, value in enumerate(data):
            z_score = (value - mean) / std_dev
            if np.abs(z_score) > threshold:
                anomalies.append((index, value))
    else:
        logger.warning("Standard deviation is zero, skipping anomaly detection.")

    return anomalies

def analyze_url(url, verify_ssl=True):
    console.print(f"\n[bold blue]Analyzing[/bold blue] {url}")
    result = {
        "url": url,
        "csp_header": None,
        "is_report_only": False,
        "directives": {},
        "issues": []
    }

    csp_header, is_report_only = get_csp_header(url, verify_ssl)
    cors_vulnerabilities = check_cors(url, verify_ssl)

    # Example data for anomaly detection (e.g., response times, CSP lengths)
    example_data = [len(csp_header) if csp_header else 0]  # Replace with actual data
    anomalies = detect_anomalies(example_data)
    if anomalies:
        logger.warning(f"Anomalies detected in {url}: {anomalies}")
        result["issues"].append({
            "type": "Anomaly Detection",
            "description": f"Anomalies detected: {anomalies}",
            "severity": "Medium",
            "recommendation": "Investigate the anomalies to understand potential issues."
        })

    result = {
        "url": url,
        "csp_header": csp_header,
        "is_report_only": is_report_only,
        "directives": {},
        "issues": []
    }

    if csp_header:
        csp_vulnerabilities, directive_dict = analyze_csp(csp_header)
        result["directives"] = directive_dict
        for vuln in csp_vulnerabilities:
            severity = get_severity(vuln)
            result["issues"].append({
                "type": "CSP Vulnerability",
                "description": vuln,
                "severity": severity,
                "recommendation": get_recommendation(vuln)
            })
    else:
        result["issues"].append({
            "type": "CSP Vulnerability",
            "description": "No CSP header found",
            "severity": "High",
            "recommendation": "Implement a strong Content Security Policy."
        })

    for cors_vuln in cors_vulnerabilities:
        severity = get_severity(cors_vuln)
        result["issues"].append({
            "type": "CORS Vulnerability",
            "description": cors_vuln,
            "severity": severity,
            "recommendation": get_recommendation(cors_vuln)
        })

    return result

def analyze_urls(url_list, max_workers=5, verify_ssl=True):
    results = []
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
    ) as progress:
        task = progress.add_task("[cyan]Analyzing URLs...", total=len(url_list))
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_url = {executor.submit(analyze_url, url, verify_ssl): url for url in url_list}
            for future in concurrent.futures.as_completed(future_to_url):
                url = future_to_url[future]
                try:
                    results.append(future.result())
                except Exception as exc:
                    console.log(f"[bold red]Error:[/bold red] {url} generated an exception: {exc}")
                finally:
                    progress.update(task, advance=1)
    return results

def create_summary_table(results):
    table = Table(title="Summary of CSP and CORS Issues", box=box.DOUBLE_EDGE)
    table.add_column("Severity", style="bold")
    table.add_column("Issue", style="dim")
    table.add_column("Count", justify="right")

    summary = defaultdict(int)
    for result in results:
        for issue in result["issues"]:
            summary[f"{issue['severity']} - {issue['description']}"] += 1

    for issue, count in sorted(summary.items(), key=lambda x: ("Medium", "High", "Critical").index(x[0].split(' - ')[0]), reverse=True):
        severity, description = issue.split(" - ")
        table.add_row(severity, description, str(count))

    return table

def create_detailed_report(results):
    console = Console()

    for result in results:
        url_panel = Panel(
            Text(result['url'], style="bold blue underline"),
            title="Analyzed URL",
            border_style="blue",
            expand=False
        )
        console.print(url_panel)

        if not result["csp_header"]:
            console.print("[bold red]No CSP Header Found[/bold red]")
            console.print("Recommendation: Implement a strong Content Security Policy")
        else:
            if result["is_report_only"]:
                console.print("[yellow]CSP in Report-Only mode[/yellow]")

            csp_table = Table(title="CSP Directives", box=box.ROUNDED, show_header=True, header_style="bold magenta")
            csp_table.add_column("Directive", style="cyan", no_wrap=True)
            csp_table.add_column("Value", style="green")

            for directive, value in result["directives"].items():
                csp_table.add_row(directive, " ".join(value))

            console.print(csp_table)

        issues_table = Table(title="Detected Issues", box=box.ROUNDED, show_header=True, header_style="bold red")
        issues_table.add_column("Type", style="cyan", no_wrap=True)
        issues_table.add_column("Description", style="yellow")
        issues_table.add_column("Severity", style="magenta")
        issues_table.add_column("Recommendation", style="green")

        for issue in result["issues"]:
            issues_table.add_row(
                issue['type'],
                issue['description'],
                issue['severity'],
                issue['recommendation']
            )

        console.print(issues_table)
        console.print()

def save_results(results, output_format, output_file=None):
    if output_file is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = f"csp_cors_analysis_{timestamp}.{output_format}"

    if output_format == 'json':
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
    elif output_format == 'html':
        html_content = f"""
        <html>
        <head>
            <title>CSP and CORS Analysis Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 800px; margin: 0 auto; padding: 20px; }}
                h1, h2, h3 {{ color: #2c3e50; }}
                .url {{ background-color: #f1f8ff; padding: 10px; border-left: 5px solid #2980b9; margin-bottom: 20px; }}
                .issue {{ background-color: #fff5f5; padding: 10px; border-left: 5px solid #e74c3c; margin-bottom: 10px; }}
                .severity-Critical {{ color: #c0392b; }}
                .severity-High {{ color: #d35400; }}
                .severity-Medium {{ color: #f39c12; }}
                pre {{ background-color: #f8f8f8; padding: 10px; overflow-x: auto; }}
                .recommendation {{ background-color: #e8f8f5; padding: 10px; border-left: 5px solid #27ae60; margin-bottom: 10px; }}
            </style>
        </head>
        <body>
            <h1>CSP and CORS Analysis Report</h1>
            <div id="summary">
                <h2>Summary</h2>
                <!-- Summary table will be inserted here -->
            </div>
            <div id="detailed-report">
                <h2>Detailed Report</h2>
                <!-- Detailed report will be inserted here -->
            </div>
        </body>
        </html>
        """

        summary_html = "<table><tr><th>Severity</th><th>Issue</th><th>Count</th></tr>"
        summary = defaultdict(int)
        for result in results:
            for issue in result["issues"]:
                summary[f"{issue['severity']} - {issue['description']}"] += 1
        for issue, count in sorted(summary.items(), key=lambda x: ("Medium", "High", "Critical").index(x[0].split(' - ')[0]), reverse=True):
            severity, description = issue.split(" - ")
            summary_html += f"<tr><td>{severity}</td><td>{description}</td><td>{count}</td></tr>"
        summary_html += "</table>"

        detailed_html = ""
        for result in results:
            detailed_html += f"<div class='url'><h3>{result['url']}</h3>"
            if not result["csp_header"]:
                detailed_html += "<p class='issue severity-High'>No CSP Header Found</p>"
                detailed_html += "<p class='recommendation'>Implement a strong Content Security Policy</p>"
            else:
                if result["is_report_only"]:
                    detailed_html += "<p>CSP in Report-Only mode</p>"
                for issue in result["issues"]:
                    detailed_html += f"<div class='issue'><h4 class='severity-{issue['severity']}'>{issue['type']}: {issue['description']}</h4>"
                    detailed_html += f"<p><strong>Severity:</strong> {issue['severity']}</p>"
                    detailed_html += f"<p class='recommendation'><strong>Recommendation:</strong> {issue['recommendation']}</p>"
                    detailed_html += "</div>"
            detailed_html += "</div>"

        html_content = html_content.replace("<!-- Summary table will be inserted here -->", summary_html)
        html_content = html_content.replace("<!-- Detailed report will be inserted here -->", detailed_html)

        with open(output_file, 'w') as f:
            f.write(html_content)

    console.print(f"[bold green]Results saved to {output_file}[/bold green]")

from poc_generator import generate_all_pocs

def main():
    parser = argparse.ArgumentParser(description="Advanced CSP and CORS Analyzer for Bug Bounty Hunters")
    parser.add_argument("-u", "--urls", nargs="+", help="List of URLs to analyze")
    parser.add_argument("-f", "--file", help="File containing URLs (one per line)")
    parser.add_argument("-w", "--workers", type=int, default=5, help="Number of worker threads (default: 5)")
    parser.add_argument("-o", "--output", choices=['json', 'html'], default='html', help="Output format (default: html)")
    parser.add_argument("--output-file", help="Output file name")
    parser.add_argument("--ignore-ssl", action="store_true", help="Ignore SSL certificate verification")
    args = parser.parse_args()

    if not args.urls and not args.file:
        parser.error("No URLs provided. Use -u/--urls or -f/--file to specify URLs.")

    url_list = []
    if args.urls:
        url_list.extend(args.urls)
    if args.file:
        try:
            with open(args.file, 'r') as f:
                url_list.extend(line.strip() for line in f if line.strip())
        except IOError as e:
            console.print(f"[bold red]Error:[/bold red] Failed to read file: {e}")
            sys.exit(1)

    verify_ssl = not args.ignore_ssl

    results = analyze_urls(url_list, args.workers, verify_ssl)

    console.print(create_summary_table(results))
    create_detailed_report(results)

    save_results(results, args.output, args.output_file)
    generate_all_pocs(results)

if __name__ == "__main__":
    main()
