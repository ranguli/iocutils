# exported_csv_to_pulse.py
# Author: Joshua Murphy
#
# Given a csv file with an "Indicator" and "Indicator type" header,
# such as one downloaded from OTX, parse the indicators out and
# upload to a pulse.
#
# If you want to combine two pulses together, this is one way to do it.
# Download one pulse as a .csv, and then run the script to upload it to
# a second pulse in order to combine the two.

from OTXv2 import OTXv2
from OTXv2 import IndicatorTypes
from decouple import config

import csv
import click

OTX_API_KEY = config("OTX_API_KEY")

otx = OTXv2(OTX_API_KEY)

indicators = []
seen = []
urls = []
domains = []


@click.command()
@click.option("--input", "input_", required=True)
@click.option("--pulse", required=True)
def main(input_, pulse):

    indicators = [] 
    total = 0

    with open(input_, "r") as f:
        rows = csv.DictReader(f)
        for index, row in enumerate(rows):
            indicator_type = row.get("Indicator type")
            indicator = row.get("Indicator")
            indicators.append({"indicator": indicator, "type": indicator_type})

            total = index
            print("({index}) Indicator {indicator} of type {indicator_type} processed.".format(index=index, indicator=indicator, indicator_type=indicator_type))

    print("Uploading {total} IOCs to OTX Pulse {pulse}.".format(total=total, pulse=pulse))
    otx.add_pulse_indicators(pulse_id=pulse, new_indicators=indicators)

if __name__ == "__main__":
    main()
