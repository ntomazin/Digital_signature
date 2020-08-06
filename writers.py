import json

def simple_writer(data: dict, path):
    with open(path, 'w') as outfile:
        json.dump(data, outfile, indent=4, sort_keys=False)

def simple_reader(path, key):
    with open(path, "r") as handle:
        dictdump = json.loads(handle.read())
    return dictdump[key]

def read_from_file(path):
    with open(path, "r") as handle:
        return handle.read()