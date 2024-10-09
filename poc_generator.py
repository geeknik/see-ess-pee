import os
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

POC_DIRECTORY = "poc_files"

if not os.path.exists(POC_DIRECTORY):
    os.makedirs(POC_DIRECTORY)

def is_valid_url(url):
    """Validate the URL format."""
    return url.startswith(('http://', 'https://'))

def generate_poc_html(vulnerability, url):
    if not is_valid_url(url):
        logger.error(f"Invalid URL: {url}")
        return
    poc_templates = {
        "unsafe-inline": """
        <!-- This POC demonstrates the 'unsafe-inline' vulnerability, which allows inline scripts to be executed. -->
        <!-- This POC demonstrates the 'unsafe-eval' vulnerability, which allows the use of eval() in scripts. -->
        <!-- This POC demonstrates a CORS vulnerability where the origin is reflected with credentials. -->
        <!-- This POC demonstrates a CORS vulnerability with wildcard and credentials. -->
        <!-- This POC demonstrates a CORS subdomain bypass vulnerability. -->
        <!-- This POC demonstrates the risk of allowing 'unsafe-inline' in script-src. -->
        <!-- This POC demonstrates the risk of missing the base-uri directive. -->
        <!-- This POC demonstrates the risk of missing the form-action directive. -->
        <!-- This POC demonstrates the risk of missing the frame-ancestors directive. -->
        <!-- This POC demonstrates the risk of missing the script-src directive. -->
        <!-- This POC demonstrates the risk of missing the object-src directive. -->
        <!-- This POC demonstrates the risk of not using nonce or strict-dynamic. -->
        <!-- This POC demonstrates a CORS vulnerability with reflected origin without credentials. -->
        <html>
        <head>
            <title>POC for unsafe-inline</title>
            <style>
                body {{ font-family: Arial, sans-serif; }}
                .warning {{ color: red; font-weight: bold; }}
            </style>
        </head>
        <body>
            <h1>POC for unsafe-inline</h1>
            <p class="warning">This page demonstrates the 'unsafe-inline' vulnerability, which allows attackers to execute arbitrary scripts.</p>
            <p>Impact: This can lead to XSS attacks, data theft, and unauthorized actions on behalf of the user.</p>
            <p>Remediation: Remove 'unsafe-inline' from your CSP and use nonces or hashes for inline scripts.</p>
            <button onclick="alert('This is an unsafe-inline script execution.'); console.log('Unsafe-inline script executed.');">Click me</button>
            <p>Inline scripts can be executed, which poses a security risk. Check the console for logs.</p>
        </body>
        </html>
        """,
        "unsafe-eval": """
        <html>
        <head>
            <title>POC for unsafe-eval</title>
            <style>
                body {{ font-family: Arial, sans-serif; }}
                .warning {{ color: red; font-weight: bold; }}
            </style>
        </head>
        <body>
            <h1>POC for unsafe-eval</h1>
            <p class="warning">This page demonstrates the 'unsafe-eval' vulnerability, which allows execution of arbitrary code.</p>
            <p>Impact: This can lead to code injection attacks, compromising the integrity of the application.</p>
            <p>Remediation: Eliminate 'unsafe-eval' from your CSP and refactor code to avoid eval().</p>
            <button onclick="eval('alert(\'This is an unsafe-eval script execution.\'); console.log(\'Unsafe-eval script executed.\')')">Click me</button>
            <p>Using eval() can execute arbitrary code, which is dangerous. Check the console for logs.</p>
        </body>
        </html>
        """,
        "Reflected origin with credentials": """
        <html>
        <head>
            <title>POC for Reflected origin with credentials</title>
            <style>
                body {{ font-family: Arial, sans-serif; }}
                .warning {{ color: red; font-weight: bold; }}
            </style>
        </head>
        <body>
            <h1>POC for Reflected origin with credentials</h1>
            <p class="warning">This page demonstrates the CORS vulnerability with reflected origin and credentials, allowing unauthorized access to sensitive data.</p>
            <p>Impact: Attackers can perform actions on behalf of authenticated users, leading to data breaches.</p>
            <p>Remediation: Implement strict origin validation and avoid reflecting user-supplied origins.</p>
            <button id="fetchData">Fetch Data</button>
            <pre id="output"></pre>
            <script>
                document.getElementById('fetchData').addEventListener('click', function() {{
                    fetch('{url}', {{
                        credentials: 'include',
                        mode: 'cors'
                    }}).then(response => response.text())
                      .then(data => {
                          document.getElementById('output').textContent = data;
                          console.log('Data fetched successfully:', data);
                      })
                      .catch(error => console.error('Error:', error));
                }});
            </script>
        </body>
        </html>
        """,
        "Wildcard CORS with credentials": """
        <html>
        <head>
            <title>POC for Wildcard CORS with credentials</title>
        </head>
        <body>
            <h1>POC for Wildcard CORS with credentials</h1>
            <p>This page demonstrates the CORS vulnerability with wildcard and credentials.</p>
            <script>
                fetch('{url}', {{
                    credentials: 'include',
                    mode: 'cors'
                }}).then(response => response.text())
                  .then(data => {
                      console.log('Data fetched successfully:', data);
                      document.body.insertAdjacentHTML('beforeend', `<pre>${data}</pre>`);
                  });
            </script>
        </body>
        </html>
        """,
        "Subdomain CORS bypass": """
        <html>
        <head>
            <title>POC for Subdomain CORS bypass</title>
        </head>
        <body>
            <h1>POC for Subdomain CORS bypass</h1>
            <p>This page demonstrates the CORS subdomain bypass vulnerability.</p>
            <script>
                fetch('{url}', {{
                    credentials: 'include',
                    mode: 'cors'
                }}).then(response => response.text())
                  .then(data => console.log(data));
            </script>
        </body>
        </html>
        """,
        "unsafe-inline allowed in script-src": """
        <html>
        <head>
            <title>POC for unsafe-inline allowed in script-src</title>
        </head>
        <body>
            <h1>POC for unsafe-inline allowed in script-src</h1>
            <p>This page demonstrates the 'unsafe-inline' vulnerability in script-src.</p>
            <script>alert('This is an unsafe-inline script execution.')</script>
        </body>
        </html>
        """,
        "Missing base-uri directive": """
        <html>
        <head>
            <title>POC for Missing base-uri directive</title>
        </head>
        <body>
            <h1>POC for Missing base-uri directive</h1>
            <p>This page demonstrates the potential risk of missing base-uri directive.</p>
            <a href="javascript:alert('This is a base-uri directive test.');">Click me</a>
        </body>
        </html>
        """,
        "Missing form-action directive": """
        <html>
        <head>
            <title>POC for Missing form-action directive</title>
        </head>
        <body>
            <h1>POC for Missing form-action directive</h1>
            <p>This page demonstrates the potential risk of missing form-action directive.</p>
            <form action="javascript:alert('Form action test');">
                <input type="submit" value="Submit">
            </form>
        </body>
        </html>
        """,
        "Missing frame-ancestors directive": """
        <html>
        <head>
            <title>POC for Missing frame-ancestors directive</title>
        </head>
        <body>
            <h1>POC for Missing frame-ancestors directive</h1>
            <p>This page demonstrates the potential risk of missing frame-ancestors directive.</p>
            <iframe src="{url}" width="600" height="400"></iframe>
        </body>
        </html>
        """,
        "Missing script-src directive": """
        <html>
        <head>
            <title>POC for Missing script-src directive</title>
        </head>
        <body>
            <h1>POC for Missing script-src directive</h1>
            <p>This page demonstrates the potential risk of missing script-src directive.</p>
            <script>alert('This script executes because there is no script-src directive.')</script>
        </body>
        </html>
        """,
        "Missing object-src directive": """
        <html>
        <head>
            <title>POC for Missing object-src directive</title>
        </head>
        <body>
            <h1>POC for Missing object-src directive</h1>
            <p>This page demonstrates the potential risk of missing object-src directive.</p>
            <object data="{url}" width="400" height="400"></object>
        </body>
        </html>
        """,
        "No CSP header found": """
        <html>
        <head>
            <title>POC for No CSP header found</title>
        </head>
        <body>
            <h1>POC for No CSP header found</h1>
            <p>This page demonstrates the risk of not having a Content Security Policy (CSP) header.</p>
            <p>Without a CSP, the application is vulnerable to various types of attacks, such as XSS.</p>
        </body>
        </html>
        """,
        "Reflected origin without credentials": """
        <html>
        <head>
            <title>POC for Reflected origin without credentials</title>
        </head>
        <body>
            <h1>POC for Reflected origin without credentials</h1>
            <p>This page demonstrates the CORS vulnerability with reflected origin without credentials.</p>
            <script>
                fetch('{url}', {{
                    mode: 'cors'
                }}).then(response => response.text())
                  .then(data => console.log(data));
            </script>
        </body>
        </html>
        """,
        "No nonce or strict-dynamic used": """
        <html>
        <head>
            <title>POC for No nonce or strict-dynamic used</title>
        </head>
        <body>
            <h1>POC for No nonce or strict-dynamic used</h1>
            <p>This page demonstrates the potential risk of not using nonce or strict-dynamic.</p>
            <script>alert('This script is executed without nonce or strict-dynamic.')</script>
        </body>
        </html>
        """,
    }

    poc_html = poc_templates.get(vulnerability)
    if poc_html:
        file_name = os.path.join(POC_DIRECTORY, f"poc_{vulnerability.replace(' ', '_').lower()}.html")
        with open(file_name, 'w') as file:
            file.write(poc_html)
        logger.info(f"POC HTML for {vulnerability} generated: {file_name}")
    else:
        logger.warning(f"No POC template available for {vulnerability}")

def generate_all_pocs(results):
    for result in results:
        for issue in result["issues"]:
            generate_poc_html(issue["description"], result["url"])
