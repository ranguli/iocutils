from OTXv2 import OTXv2
from OTXv2 import IndicatorTypes
from decouple import config

API_KEY = config('API_KEY')
otx = OTXv2(API_KEY)

ip = "193.35.50.251"
indicators = []
seen = []

print("Getting results for {ip}".format(ip=ip))
results = otx.get_indicator_details_by_section(IndicatorTypes.IPv4, ip, section='passive_dns')
indicators.append({'indicator': ip, 'type': 'IPv4'})

safebrowsing_malicious = []

if results.get('google_safebrowsing') == 'malicious':
    safebrowsing_malicious.append(ip)
results = results.get('passive_dns')

for result in results:
    if result.get('google_safebrowsing') == 'malicious':
        safebrowing_malicious.append(result.get('hostname'))

    domain = result.get("hostname")
    if domain not in seen:
        seen.append(domain)
        print("> Got domain {domain}".format(domain=domain))
        indicators.append({'indicator': domain, 'type': 'Domain'})
    else:
        pass

    sub_results  = otx.get_indicator_details_by_section(IndicatorTypes.DOMAIN, domain, section='url_list')
    if not sub_results.get('url_list'):
        print("    > No other urls associated with {url}".format(url=url))
    else:
        for url in sub_results.get('url_list'):
            url = url.get("url")
            if url not in seen:
                indicators.append({'indicator': domain, 'type': 'URL'})
                seen.append(url)
                print("   > Got url {url}".format(url=url))
            else:
                pass

response = otx.create_pulse(name="Russian Spam/Phishing Campaign", public=True, indicators=indicators, tags=[], references=[])

print("The following were marked as suspicious by google safebrowsing:")
print("\n".join(safebrowsing_malicious))

with open('iocs.txt', 'w') as f:
    print("Writing iocs to plaintext.")
    f.write("\n".join(seen))
