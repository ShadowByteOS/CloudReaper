# CloudReaper 2.0

A powerful Python OSINT (Open Source INTelligence) tool designed to uncover the real IP addresses behind Cloudflare-protected websites. CloudReaper employs a combination of advanced techniques to bypass Cloudflare's protections and reveal the underlying infrastructure.

## ⚠️ Ethical Disclaimer ⚠️

This tool was developed for **educational and cybersecurity research purposes only**. The use of CloudReaper for illegal or unauthorized activities is **strictly prohibited**. The author assumes no responsibility for the misuse of this software. Use it only on systems you own or for which you have explicit authorization.

## Features

-   **Advanced DNS Bruteforce:** Discovers hidden subdomains and verifies if they point to real, non-Cloudflare protected IP addresses.
-   **HTTP/S Verification with Host Header:** Checks if discovered IPs respond to HTTP/S requests using the target domain's Host header, simulating browser behavior.
-   **Reverse DNS Lookup:** Performs reverse DNS lookups to identify if an IP is associated with a domain name that could reveal infrastructure.
-   **"Stealth" Mode (Optional):** Utilizes randomized User-Agents and introduces random delays between requests to reduce detection risk.
-   **Colorful Output and Animations:** Intuitive CLI interface with vibrant colored output and loading animations for an enhanced user experience.
-   **Detailed Report:** Generates a comprehensive text report with all discovered IPs, their origin, HTTP/S verification results, and Reverse DNS information.
-   **JSON Output (Optional):** Ability to export results in JSON format for easy integration with other tools or for automated analysis.

## Installation

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/ShadowByteOS/CloudReaper.git
    cd CloudReaper
    ```

2.  **Install Python dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

## Usage

```bash
python CloudReaper.py -d <target_domain> [options]
```
![ChatGPT Image 30 giu 2025, 16_55_45](https://github.com/user-attachments/assets/5a2be6eb-5eba-47ce-bb44-08d62fdf976e)

**Examples:**

-   **Basic scan:**
    ```bash
    python CloudReaper.py -d example.com
    ```

-   **Scan with a custom wordlist:**
    ```bash
    python CloudReaper.py -d example.com -w my_wordlist.txt
    ```

-   **Stealth mode scan with JSON output:**
    ```bash
    python CloudReaper.py -d example.com --stealth --json
    ```

-   **Specify an output file:**
    ```bash
    python CloudReaper.py -d example.com -o my_report
    ```
    (This will generate `my_report.txt` and `my_report.json` if `--json` is enabled)

### CLI Arguments

-   `-d`, `--domain` (Required): The target domain (e.g., `example.com`).
-   `-w`, `--wordlist` (Optional): Path to a custom subdomain wordlist file. If not specified, a default wordlist will be used.
-   `-o`, `--output` (Optional): Base name for report output files (e.g., `report-target.txt`, `report-target.json`).
-   `-t`, `--threads` (Optional): Number of threads to use for parallel operations (default: 50).
-   `--stealth` (Flag): Enables stealth mode with randomized User-Agents and random delays between requests.
-   `--json` (Flag): Enables report output in JSON format.

## API Keys (Optional)

CloudReaper can integrate data from external services like SecurityTrails and Shodan to enrich results. To use these features, you need to obtain your API keys and set them as **environment variables**:

-   `SECURITYTRAILS_API_KEY`: Your API key from [securitytrails.com](https://securitytrails.com/)
-   `SHODAN_API_KEY`: Your API key from [shodan.io](https://www.shodan.io/)

**How to set environment variables (Example for Windows Command Prompt):**
```bash
setx SECURITYTRAILS_API_KEY "YOUR_SECURITYTRAILS_API_KEY"
setx SHODAN_API_KEY "YOUR_SHODAN_API_KEY"
```

**How to set environment variables (Example for Linux/macOS Bash):**
```bash
export SECURITYTRAILS_API_KEY="YOUR_SECURITYTRAILS_API_KEY"
export SHODAN_API_KEY="YOUR_SHODAN_API_KEY"
```

**Note:** If these keys are not provided, the tool will still function based on its other discovery techniques.

## Contributions

Contributions are welcome! If you have ideas to improve CloudReaper, feel free to open an issue or submit a pull request.

## License

This project is released under the MIT License. See the `LICENSE` file for more details.
