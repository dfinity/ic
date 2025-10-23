#!/usr/bin/python3
import sys
import json

def transform(data):
    if data is None:
        return None
    data = data[0]
    type_name = data["type_name"][0]
    type_description = data["type_description"][0]
    value = data["value"][0]
    return {
        "type_name": type_name,
        "type_description": type_description,
        "value": transform_value(value)
    }

def transform_value(value):
    if "Map" in value:
        return transform_map(value["Map"])
    elif "Array" in value:
        return transform_array(value["Array"])
    elif "Text" in value:
        return value["Text"]
    elif "Nat" in value:
        return int(value["Nat"])
    elif "Int" in value:
        return int(value["Int"])
    elif "Blob" in value:
        return transform_blob(value["Blob"])
    else:
        return None

def transform_map(map):
    result = {}
    for entry in map:
        key = entry["0"]
        value = entry["1"]
        result[key] = transform_value(value)
    return result

def transform_array(array):
    return [transform_value(value) for value in array]

def transform_blob(blob):
    return bytes(blob).hex()

def main():
    data = json.load(sys.stdin)
    result = transform(data)
    json.dump(result, sys.stdout, indent=2)
    sys.stdout.write('\n')

if __name__ == "__main__":
    main()
