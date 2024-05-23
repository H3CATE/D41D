import time
import requests
import argparse
import configparser
from colorama import init, Fore, Style

# Initialize colorama
init(autoreset=True)

#Initialize API_KEYS: 

config = configparser.ConfigParser()
config.read('api_keys.ini')

# Fetch API Keys from file
TRIAGE_API_KEY = config['API_KEYS']['TRIAGE_API_KEY']
VIRUSTOTAL_API_KEY = config['API_KEYS']['VIRUSTOTAL_API_KEY']
print(TRIAGE_API_KEY,VIRUSTOTAL_API_KEY)

def fetch_detailed_report(task_url, headers, retries=5, delay=10):
    for _ in range(retries):
        detailed_report_response = requests.get(task_url, headers=headers)
        detailed_report = detailed_report_response.json()
        
        if detailed_report_response.status_code == 200:
            return detailed_report
        else:
            print(f"{Fore.YELLOW}Detailed report not available yet, retrying in {delay} seconds...")
            time.sleep(delay)
    
    print(f"{Fore.RED}Failed to fetch the detailed report after multiple attempts.")
    return None

def analyze_with_triage(file_path):
    headers = {
        'Authorization': f'Bearer {TRIAGE_API_KEY}'
    }
    
    with open(file_path, 'rb') as file:
        files = {'file': file}
        response = requests.post('https://api.tria.ge/v0/samples', headers=headers, files=files)
        response_data = response.json()
        
        if 'id' not in response_data:
            print(f"{Fore.RED}Failed to upload file to Triage.")
            print("Response:", response_data)
            return None

        task_id = response_data['id']
        task_url = f'https://api.tria.ge/v0/samples/{task_id}'
        report_url = f'https://api.tria.ge/v0/samples/{task_id}/overview.json'

        print(f"{Fore.GREEN}Monitor the behavior at: {Fore.CYAN}https://tria.ge/{task_id}/behavioral1")

        while True:
            task_response = requests.get(task_url, headers=headers)
            task_data = task_response.json()
            status = task_data.get('status')
            
            if status == 'reported':
                break
            elif status == 'failed':
                print(f"{Fore.RED}Triage analysis failed.")
                return None
            else:
                print(f"{Fore.YELLOW}Current status: {status}", end='\r', flush=True)
                time.sleep(5)  # Check every 5 seconds

        print(f"\n{Fore.GREEN}Triage analysis completed!")
        
        detailed_report = fetch_detailed_report(report_url, headers)
        detailed_report['id'] = task_id  # Add task_id to detailed report
        
        return detailed_report

def analyze_with_virustotal(file_path):
    headers = {
        'x-apikey': VIRUSTOTAL_API_KEY
    }
    
    with open(file_path, 'rb') as file:
        files = {'file': file}
        response = requests.post('https://www.virustotal.com/api/v3/files', headers=headers, files=files)
        response_data = response.json()
        
        if 'data' not in response_data:
            print(f"{Fore.RED}Failed to upload file to VirusTotal.")
            print("Response:", response_data)
            return None

        analysis_id = response_data['data']['id']
        analysis_url = f'https://www.virustotal.com/api/v3/analyses/{analysis_id}'

        timeout = 600  # maximum timeout of 10 minutes
        start_time = time.time()

        while True:
            analysis_response = requests.get(analysis_url, headers=headers)
            analysis_data = analysis_response.json()
            status = analysis_data['data']['attributes']['status']
            
            if status == 'completed':
                break
            elif status in ['queued', 'in-progress']:
                if time.time() - start_time > timeout:
                    print(f"{Fore.RED}VirusTotal analysis timed out.")
                    return None
                else:
                    print(f"{Fore.YELLOW}Current VT status: {status}", end='\r', flush=True)
                    time.sleep(5)  # Check every 5 seconds
            else:
                print(f"{Fore.RED}Unexpected status: {status}")
                return None

        print(f"\n{Fore.GREEN}VirusTotal analysis completed!")
        
        return analysis_data

def print_triage_report(report):
    score = report.get('analysis', {}).get('score', 0)
    if score <= 3:
        severity_color = Fore.GREEN
    elif score <= 7:
        severity_color = Fore.YELLOW
    else:
        severity_color = Fore.RED

    banner = f"""
    {severity_color}{Style.BRIGHT}============================
    TRIAGE DETAILED ANALYSIS RESULT
    ============================
    """
    print(banner)
    
    sample_info = report.get('sample', {})
    print(f"{Fore.CYAN}Sample Information:")
    print(f"{Fore.WHITE}  ID: {severity_color}{sample_info.get('id')}")
    print(f"{Fore.WHITE}  File Name: {severity_color}{sample_info.get('target')}")
    print(f"{Fore.WHITE}  MD5: {severity_color}{sample_info.get('md5')}")
    print(f"{Fore.WHITE}  SHA1: {severity_color}{sample_info.get('sha1')}")
    print(f"{Fore.WHITE}  SHA256: {severity_color}{sample_info.get('sha256')}")
    print(f"{Fore.WHITE}  Size: {severity_color}{sample_info.get('size')} bytes")
    print(f"{Fore.WHITE}  Analysis Score: {severity_color}{sample_info.get('score')}")

    analysis_info = report.get('analysis', {})
    print(f"{Fore.CYAN}\nAnalysis Information:")
    print(f"{Fore.WHITE}  Score: {severity_color}{analysis_info.get('score')}")

    signatures = report.get('signatures', [])
    if signatures:
        print(f"{Fore.CYAN}\nSignatures:")
        for sig in signatures:
            print(f"{Fore.WHITE}  - {severity_color}{sig.get('name')}{Fore.WHITE}: {sig.get('desc')} (Score: {severity_color}{sig.get('score')})")

    targets = report.get('targets', [])
    if targets:
        print(f"{Fore.CYAN}\nIndicators of Compromise (IoCs):")
        for target in targets:
            iocs = target.get('iocs', {})
            domains = iocs.get('domains', [])
            ips = iocs.get('ips', [])
            urls = iocs.get('urls', [])

            if domains:
                print(f"{Fore.WHITE}  Domains:")
                for domain in domains:
                    print(f"{Fore.WHITE}    - {severity_color}{domain}")

            if ips:
                print(f"{Fore.WHITE}  IPs:")
                for ip in ips:
                    print(f"{Fore.WHITE}    - {severity_color}{ip}")

            if urls:
                print(f"{Fore.WHITE}  URLs:")
                for url in urls:
                    print(f"{Fore.WHITE}    - {severity_color}{url}")

    print(f"{Fore.CYAN}\nTriage Report Link: {Fore.CYAN}https://tria.ge/{report['id']}")
    
def print_virustotal_report(report):
    results = report['data']['attributes']['results']
    score = sum(1 for result in results.values() if result['category'] == 'malicious')
    severity_color = Fore.RED if score > 0 else Fore.GREEN
    banner = f"""
    {severity_color}{Style.BRIGHT}============================
    VIRUSTOTAL ANALYSIS RESULT
    ============================
    """
    print(banner)
    
    data = report['data']
    print(f"{Fore.CYAN}Analysis Information:")
    print(f"{Fore.WHITE}  ID: {severity_color}{data['id']}")
    print(f"{Fore.WHITE}  Analysis Date: {severity_color}{data['attributes']['date']}")
    print(f"{Fore.WHITE}  Malicious Detections: {severity_color}{score}")

    for engine, result in results.items():
        if result['category'] == 'malicious':
            print(f"{Fore.WHITE}  - {severity_color}{engine}: {result['result']}")

def main(file_path):
    print(f"{Fore.CYAN}Starting analysis with Triage and VirusTotal...")
    
    triage_result = analyze_with_triage(file_path)
    virustotal_result = analyze_with_virustotal(file_path)

    if triage_result:
        print_triage_report(triage_result)
    else:
        print(f"{Fore.RED}Triage analysis failed or detailed report not available.")

    if virustotal_result:
        print_virustotal_report(virustotal_result)
    else:
        print(f"{Fore.RED}VirusTotal analysis failed or detailed report not available.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Analyze a file with Triage and VirusTotal")
    parser.add_argument('file_path', help="Path to the file to be analyzed")
    args = parser.parse_args()
    
    main(args.file_path)