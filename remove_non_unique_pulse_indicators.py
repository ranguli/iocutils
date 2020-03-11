from OTXv2 import OTXv2
from OTXv2 import IndicatorTypes
from decouple import config
import click
import requests
from pprint import PrettyPrinter

OTX_API_KEY = config("OTX_API_KEY")

otx = OTXv2(OTX_API_KEY)

@click.command()
@click.option('-p', '--pulse', 'pulse_id', required=True, help="The ID of the pulse you wish to download indicators from.")
@click.option('-c', '--cutoff', 'cutoff', default=15, help="The ID of the pulse you wish to download indicators from.")
def main(pulse_id, cutoff):
    
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

if __name__ == "__main__":
    main()
