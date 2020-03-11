# download_pulse.py
# Author: Joshua Murphy
#
# Download all of the indicators from a pulse into plaintext.
# Can be used for the creation of wordlists, blacklists, blocklists,
# or any other creative purpose you can come up with.

from OTXv2 import OTXv2
from decouple import config
import click

OTX_API_KEY = config("OTX_API_KEY")

otx = OTXv2(OTX_API_KEY)


@click.command()
@click.option(
    "-p",
    "--pulse",
    "pulse_id",
    required=True,
    help="The ID of the pulse you wish to download indicators from.",
)
@click.option(
    "-o",
    "--out",
    "outfile",
    required=True,
    help="The ID of the pulse you wish to download indicators from.",
)
def main(pulse_id, outfile):

    indicators = otx.get_pulse_indicators(pulse_id)
    with open(outfile, "a") as f:
        for indicator in indicators:
            name = indicator.get("indicator")
            print(f"Downloading {name}")
            f.write(indicator.get("indicator") + "\n")


if __name__ == "__main__":
    main()
