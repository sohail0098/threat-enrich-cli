# 🕵️ Threat Intel Enrichment CLI

A Python CLI tool for enriching IOCs (IPs, domains, hashes) with public threat intelligence APIs.

## Features
- Supports single IOC or bulk file input
- Queries AbuseIPDB for IP reputation data
- Outputs results in console or JSON format
- Extensible design for adding other APIs (OTX, VirusTotal, etc.)
- Easy on the eyes
- Summary of IOC enrichment

## Setup
1. Clone this repo  
   ```bash
   git clone https://github.com/sohail0098/threat-enrich-cli.git
   cd threat-enrich-cli
   ```

2. Install dependencies (vitual env recommended)
    ```bash
    pip install -r requirements.txt
    ```

3. Add your API keys to `config.yml`

4. Run examples
    ```bash
    python src/main.py --input 8.8.8.8
    python src/main.py --file examples/sample_iocs.txt --output results.json
    ```

### Example Output
```bash
+--------------+-----------+---------------+-----------+----------+-------------------------------------------------------------------------------+---------+
| IOC          | Source    | Abuse Score   | Reports   | Pulses   | Tags                                                                          | Error   |
+==============+===========+===============+===========+==========+===============================================================================+=========+
| 8.8.8.8      | AbuseIPDB | 0             | 161       | -        | -                                                                             | -       |
+--------------+-----------+---------------+-----------+----------+-------------------------------------------------------------------------------+---------+
| 8.8.8.8      | OTX       | -             | -         | 0        | -                                                                             | -       |
+--------------+-----------+---------------+-----------+----------+-------------------------------------------------------------------------------+---------+
| 1.1.1.1      | AbuseIPDB | 0             | 203       | -        | -                                                                             | -       |
+--------------+-----------+---------------+-----------+----------+-------------------------------------------------------------------------------+---------+
| 1.1.1.1      | OTX       | -             | -         | 0        | -                                                                             | -       |
+--------------+-----------+---------------+-----------+----------+-------------------------------------------------------------------------------+---------+
| 45.33.32.156 | AbuseIPDB | 0             | 0         | -        | -                                                                             | -       |
+--------------+-----------+---------------+-----------+----------+-------------------------------------------------------------------------------+---------+
| 45.33.32.156 | OTX       | -             | -         | 3        | C&C-IP-List, Python: OVSAgentServer Document (autofilled name), Cobalt Strike | -       |
+--------------+-----------+---------------+-----------+----------+-------------------------------------------------------------------------------+---------+
```