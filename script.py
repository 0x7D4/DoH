import json
import subprocess

# Load the websites from the JSON file
with open('ranked_domains.json') as f:
    websites = json.load(f)

# Loop through each entry in the list
for website in websites:
    domain = website['domain']
    command = f'curl --doh-insecure --doh-url https://10.0.2.15/dns-query https://www.{domain} -v'
    print(f'Running command: {command}')
    subprocess.run(command, shell=True)
