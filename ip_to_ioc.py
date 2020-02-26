from OTXv2 import OTXv2
from OTXv2 import IndicatorTypes
from decouple import config
from virus_total_apis import PublicApi as VirusTotalPublicApi
import click
import requests

OTX_API_KEY = config("OTX_API_KEY")
VT_API_KEY = config("VT_API_KEY")

otx = OTXv2(OTX_API_KEY)

indicators = []
seen = []
urls = []
domains = []


@click.command()
@click.option("--ip", required=True)
@click.option('--publish', 'publish', flag_value='publish', default=False)
@click.option("--pulse")
def main(ip, publish, pulse):

    print("Getting information from VirusTotal")

    url = "https://www.virustotal.com/vtapi/v2/ip-address/report"
    params = {"apikey": VT_API_KEY, "ip": ip}
    response = requests.get(url, params=params)
    response = response.json()

    undetected_downloaded_samples = response.get("undetected_downloaded_samples")
    detected_downloaded_samples = response.get("detected_downloaded_samples")

    undetected_urls = response.get("undetected_urls")
    detected_urls = response.get("detected_urls")

    for undetected_url in undetected_urls:
        url = undetected_url[0]
        if url not in seen:
            seen.append(url)
            print("Found associated URL {url} on VirusTotal".format(url=url))
            indicators.append({"indicator": url, "type": url})

    for detected_url in detected_urls:
        url = detected_url.get("url")
        if url not in seen:
            seen.append(url)
            print("Found associated URL {url} on VirusTotal".format(url=url))
            indicators.append({"indicator": url, "type": url})

    for undetected_downloaded_sample in undetected_downloaded_samples:
        sample_hash = undetected_downloaded_sample.get("sha256")
        if sample_hash not in seen:
            seen.append(sample_hash)
            print("Found associated hash {sample_hash} on VirusTotal".format(sample_hash=sample_hash))
            indicators.append({"indicator": sample_hash, "type": "FileHash-SHA256"})

    for detected_downloaded_sample in detected_downloaded_samples:
        sample_hash = detected_downloaded_sample.get("sha256")
        if sample_hash not in seen:
            seen.append(sample_hash)
            print("Found associated hash {sample_hash} on VirusTotal".format(sample_hash=sample_hash))
            indicators.append({"indicator": sample_hash, "type": "FileHash-SHA256"})

    print("Getting OTX results for {ip}".format(ip=ip))
    results = otx.get_indicator_details_full(IndicatorTypes.IPv4, ip)
    indicators.append({"indicator": ip, "type": "IPv4"})

    ignore = ["general", "geo", "nids_list", "http_scans"]
    for section in results.get("general").get("sections"):
        if section in ignore:
            pass
        elif section == "passive_dns":
            passive_dns = results.get("passive_dns").get("passive_dns")
            for entry in passive_dns:
                domain = entry.get("hostname")
                print("Found associated domain {domain} on OTX".format(domain=domain))
                if domain not in seen:
                    domains.append(domain)
                    seen.append(domain)
                    indicators.append({"indicator": domain, "type": "domain"})
        elif section == "url_list":
            url_list = results.get("url_list").get("url_list")
            for associated_url in url_list:
                url = associated_url.get("url")
                print("Found URL {url}".format(url=url))
                if url not in seen:
                    urls.append(url)
                    seen.append(url)
                    indicators.append({"indicator": url, "type": "url"})
        elif section == "reputation":
            reputation = results.get(section)
            if not reputation.get("reputation"):
                pass
            else:
                print(
                    "Reputation value associated with IP is {reputation}".format(
                        reputation=reputation
                    )
                )
        elif section == "malware":
            malware = results.get(section)
            if not malware.get("malware"):
                pass
            else:
                print("Malware associated with IP is {malware}".format(malware=malware))

    if pulse:
        print("Uploading IOCs to OTX Pulse {pulse}.".format(pulse=pulse))
        otx.add_pulse_indicators(pulse_id=pulse, new_indicators=indicators)
    if publish:
        public=False

        pulse_name = click.prompt("Enter the name for the new OTX pulse")
        tags = click.prompt("Enter tags separated by commas (leave empty for none)")

        if tags:
            tags = tags.split(",")
        elif not tags:
            tags = []

        if click.confirm("Make the pulse public?"):
            public = True

        if click.confirm("About to create a new pulse. Launch the missiles?"):
            print("Uploading IOCs to OTX!")
            response = otx.create_pulse(name=pulse_name, public=public, indicators=indicators, tags=tags, references=[])
            print(str(response))

    with open("iocs.txt", "w") as f:
        print("Writing all IOCS to plaintext.")
        f.write("\n".join(seen))


if __name__ == "__main__":
    main()
