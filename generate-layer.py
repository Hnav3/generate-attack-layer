import json
import argparse
import csv
import sys

# Static ATT&CK Navigator layer JSON fields
LAYER_VERSION = "4.3"
NAV_VERSION = "4.0"
NAME = "LAYERNAME"
DESCRIPTION = "DESCRIPTION OF LAYER"
DOMAIN = "enterprise-attack"

# Base ATT&CK Navigation layer
layer_json = {
    "versions": {
        "layer": LAYER_VERSION,
        "navigator": NAV_VERSION
    },
    "name": NAME,
    "description": DESCRIPTION,
    "domain": DOMAIN,
    "techniques": [],
    "gradient": {
        "colors": [
            "#ffffff",
            "#ff6666"
        ],
        "minValue": 0,
        "maxValue": 5
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
                        t["score"] = t["score"]+1
                        metadata = {"name":row["dataSource"],"value":row["useCase"]}
                        t["metadata"].append(metadata)

    
    with open('layer.json','w') as jsonfile:
        json.dump(layer_json,jsonfile, indent=4)


if __name__ == "__main__":
    parser = arg_parse()
    args = parser.parse_args()
    main(args)
