import urllib.request, json

source = 'https://dissect.crocs.fi.muni.cz/'
query = {"standard":True}

def prepare_identifiers(curves):
    identifier_dictionary = {}
    identifiers = set()
    bad_identifiers = set()
    for curve,field,params in curves:
        params = [params.get(coef,{}) for coef in ["a","b","c","d"]]
        params = [hex(param["raw"]) for param in filter(lambda x: "raw" in x,params)]
        params = list(set(filter(lambda x: int(x,16).bit_length()>20,params)))
        identifiers.add(curve)
        identifier_dictionary[curve.lower()] = curve
        if "p" in field:
            params.append(hex(field["p"]))
        for param in params:
            if param in bad_identifiers:
                continue
            if param in identifiers:
                identifiers.remove(param)
                identifier_dictionary.pop(param)
                bad_identifiers.add(param)
            else:
                identifiers.add(param)
                identifier_dictionary[param] = curve
    return identifiers, identifier_dictionary



if __name__=="__main__":
    args = []
    for key in query:
        if isinstance(query[key], list):
            for item in query[key]:
                args.append(f"{key}={item}")
        else:
            args.append(f"{key}={query[key]}")
    args = "&".join(args)

    req = urllib.request.Request(f"{source}db/curves?{args}", method="GET")

    with urllib.request.urlopen(req) as f:
        curves = json.loads(f.read())["data"]

    curves = list(map(lambda x: (x["name"],x["field"],x["params"]),curves))


    filepath = "cryptodetector/methods/keyword/ec_list.txt"
    filepath_dict = "cryptodetector/methods/keyword/ec_list_dict"

    identifiers, identifier_dictionary = prepare_identifiers(curves)
    with open(filepath,"w") as f:
        f.write('[keyword_list_version]\n\t6\n\n[{"evidence_type": "algorithm/asymmetric/ECC", "language": "all"}]\n')
        for identifier in identifiers:
            f.write(f'\t\"{identifier}\"\n')

    with open(filepath_dict, "w") as f:
        json.dump(identifier_dictionary,f)

    print(f"{len(curves)} curves saved to {filepath}")
