import json
import argparse
import csv
import sys

from mitreattack.navlayers import Layer
from mitreattack.navlayers import ToSvg, SVGConfig

# Static ATT&CK Navigator layer JSON fields
ATTACK_VERSION = "12"
LAYER_VERSION = "4.3"
NAV_VERSION = "4.8.0"
NAME = "ATT&CK Coverage"
DESCRIPTION = "Coverage of MITRE ATT&CK techniques"
DOMAIN = "enterprise-attack"

# Base ATT&CK Navigation layer
layer_json = {
    "versions": {
        "layer": LAYER_VERSION,
        "navigator": NAV_VERSION,
        "attack": ATTACK_VERSION
    },
    "name": NAME,
    "description": DESCRIPTION,
    "domain": DOMAIN,
    "filters": {
        "platforms": [
            "Linux",
            "macOS",
            "Windows",
            "Containers",
            "Office 365",
            "SaaS",
            "Google Workspace",
            "IaaS",
            "Azure AD",
            "Network",
            "PRE"
        ]
    },
    "layout": {
        "layout": "side",
        "showID": True,
        "showName": True,
    },
    "selectTechniquesAcrossTactics": True,
    "showTacticRowBackground": True,
    "selectSubtechniquesWithParent": True,
    "techniques": [],
    "gradient": {
        "colors": [
            "#ffffffff",
            "#66a0ffff"
        ],
        "minValue": 0,
        "maxValue": 1
    }
}

def add_technique(row):
    technique = {
        "techniqueID": row["techID"],
        "score": 1,
        "metadata": [{"name":row["dataSource"],"value":row["useCase"]}]
        }
        
    layer_json["techniques"].append(technique)

def arg_parse():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--input", action="store", dest="input_fn", default="attack.csv",
                        required=True, help="input ATT&CK csv file")
    parser.add_argument("-s","--svg", action="store_true", dest="to_svg", help="Output layer to svg file.")

    return parser 

def main(args):

    with open(args.input_fn, "r") as csvfile:
        reader = csv.DictReader(csvfile, delimiter=",")
        for row in reader:
            if not any(x['techniqueID'] == row["techID"] for x in layer_json["techniques"]):
                add_technique(row)
            else:
                for t in layer_json["techniques"]:
                    if t["techniqueID"] == row["techID"]:
                        metadata = {"name":row["dataSource"],"value":row["useCase"]}
                        t["metadata"].append(metadata)

    if args.to_svg == True:
        lay = Layer()
        lay.from_dict(layer_json)
        
        svg_config = SVGConfig()
        svg_config.load_from_file(filename='svg_config.json')
        t = ToSvg(domain=lay.layer.domain, source='local', resource='attack_data/enterprise-attack.json', config=svg_config)
        t.to_svg(layerInit=lay, filepath = "attack_coverage.svg")

    else: 
        with open('layer.json','w') as jsonfile:
            json.dump(layer_json,jsonfile, indent=4)


if __name__ == "__main__":
    parser = arg_parse()
    args = parser.parse_args()
    main(args)