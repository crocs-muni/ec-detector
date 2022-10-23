import urllib.request, json

source = 'https://dissect.crocs.fi.muni.cz/'
query = {"standard":True}

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

curves = list(map(lambda x: x["name"],curves))


filepath = "cryptodetector/methods/keyword/ec_list.txt"

with open(filepath,"w") as f:
    f.write('[keyword_list_version]\n\t6\n\n[{"evidence_type": "algorithm/asymmetric/ECC", "language": "all"}]\n')
    for curve in curves:
        f.write(f'\t\"{curve}\"\n')

print(f"{len(curves)} curves saved to {filepath}")
