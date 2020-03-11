from OTXv2 import OTXv2
from OTXv2 import IndicatorTypes
from decouple import config
import click
from pprint import PrettyPrinter

OTX_API_KEY = config("OTX_API_KEY")

otx = OTXv2(OTX_API_KEY)

supported_types = {supported_type.name:supported_type for (supported_type) in IndicatorTypes.all_types}

@click.command()
@click.option('-i', '--indicator', 'indicator', required=True, help="The indicator you want details on ")
@click.option('-t', "--type", "indicator_type", type=click.Choice(supported_types.keys(), case_sensitive=False), help="The type of your indicator")
def main(indicator, indicator_type):

        full_details = otx.get_indicator_details_full(supported_types.get(indicator_type), indicator)

        pp = PrettyPrinter()
        pp.pprint(full_details)

if __name__ == "__main__":
    main()
