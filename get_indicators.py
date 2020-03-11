from OTXv2 import OTXv2
from OTXv2 import IndicatorTypes
from decouple import config
import click

OTX_API_KEY = config("OTX_API_KEY")
otx = OTXv2(OTX_API_KEY)

indicators = []
seen = []
urls = []
domains = []


indicator_types_lookup = { valid_type.name:valid_type for (valid_type) in IndicatorTypes.all_types }

@click.command()
@click.option("-i", "--indicator", required=True, help="The indicator you more details on.")
@click.option('-t', "--type", "indicator_type", required = True, type=click.Choice(indicator_types_lookup.keys(), case_sensitive=False), help="The type of your indicator")
@click.option("--publish", "publish", flag_value="publish", default=False)
@click.option("--pulse")
@click.option("-o", "--out", required=True)
def main(indicator, indicator_type, publish, pulse, out):

    print(f"Getting OTX results for {indicator}")
    results = otx.get_indicator_details_full(indicator_types_lookup.get(indicator_type), indicator)
    indicators.append({"indicator": indicator, "type": indicator_type})

    if raw:
        pp.pprint(results)
        return

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
        # Check the IOC to see if its already in a lot of pulses

        unique_iocs = []
        for indicator in indicators:

            indicator_name = indicator.get("indicator")
            indicator_type = indicator_type_lookup.get(indicator.get("type"))
            related_pulse_count = results["general"]["pulse_info"]["count"]

            if related_pulse_count < 20:
                print(
                    f"Indicator {indicator_name} is in {related_pulse_count} other pulses, it is unique.. Good find!"
                )
                unique_iocs.append({"indicator": indicator, "type": indicator_type})

        print("Uploading IOCs to OTX Pulse {pulse}.".format(pulse=pulse))
        otx.add_pulse_indicators(pulse_id=pulse, new_indicators=indicators)

    if publish:
        public = False

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
            response = otx.create_pulse(
                name=pulse_name,
                public=public,
                indicators=indicators,
                tags=tags,
                references=[],
            )
            print(str(response))

    with open(out, "w") as f:
        print("Writing all IOCS to plaintext.")
        f.write("\n".join(seen))


if __name__ == "__main__":
    main()
