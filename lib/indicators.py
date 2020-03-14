from typing import Union
import io
import ipaddress
import re

from OTXv2 import OTXv2
from OTXv2 import IndicatorTypes
from decouple import config

OTX_API_KEY = config("OTX_API_KEY")
otx = OTXv2(OTX_API_KEY)


indicator_types_lookup = { valid_type.name:valid_type for (valid_type) in IndicatorTypes.all_types }

def remove_non_indicators_from_pulse(pulse_id, threshold):
    
    print("Getting pulse indicators for pulse {pulse_id}".format(pulse_id=pulse_id))
    indicators = otx.get_pulse_indicators(pulse_id)

    for possible_indicator in indicators:
        indicator = possible_indicator.get("indicator")
        indicator_type = possible_indicator.get("type")

        for supported_type in IndicatorTypes.all_types:
            if possible_indicator.get("type") == supported_type.name:
                indicator_type = supported_type
                break

        full_details = otx.get_indicator_details_full(indicator_type, indicator)

        related_pulse_count = full_details.get("general").get("pulse_info").get("count")
        related_pulses = full_details.get("general").get("pulse_info").get("pulses")
        indicator_id = full_details.get("general").get("base_indicator").get("id")
        
        if related_pulse_count - 1 > cutoff:
            otx.remove_pulse_indicators(pulse_id, [indicator_id])
            print("Removed indicator {indicator} (ID #{indicator_id}) that was present in {related_pulse_count} other pulses.".format(indicator=indicator, indicator_id=indicator_id, related_pulse_count=related_pulse_count))
        else:
            print("Did not delete {indicator} (ID #{indicator_id}), it was only present in {related_pulse_count} pulses.".format(indicator=indicator, indicator_id=indicator_id, related_pulse_count=related_pulse_count))

def guess_indicator_type(indicator: str) -> IndicatorTypes.IndicatorTypes:
    try:
        ipaddress.ip_address(item.split("://")[-1])
    except ValueError
        pass
    

def extract_indicators(data: Union[io.TextIOBase, str]):
    
    if isinstance(data, str):
        raw = data.split()
    elif isinstance(data, io.TextIOBase):
        raw = [item for line in data for item in line.split()]

    for item in raw:


    print(raw) 

    return data

def get_otx_indicator(indicator, indicator_type):
    indicators = []
    seen = []
    urls = []
    domains = []

    print(f"Getting OTX results for {indicator}")
    results = otx.get_indicator_details_full(indicator_types_lookup.get(indicator_type), indicator)
    indicators.append({"indicator": indicator, "type": indicator_type})

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

    return indicators 

def get_unique_indicators(results):
    unique_indicators = []
    for indicator in results:

        indicator_name = indicator.get("indicator")
        indicator_type = indicator_type_lookup.get(indicator.get("type"))
        related_pulse_count = results["general"]["pulse_info"]["count"]

        if related_pulse_count < 20:
            print(
                f"Indicator {indicator_name} is in {related_pulse_count} other pulses, it is unique.. Good find!"
            )
            unique_indicators.append({"indicator": indicator, "type": indicator_type})

    return unique_indicators
