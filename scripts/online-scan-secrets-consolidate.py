import os
import json
# Generate a single Gitleaks consolidated data file
# from differents ones generated with the script "online-scan-secrets.sh"
base = "data-collected"
output = "leaks-consolidated.json"
leaks = []
for gitleaks_file in os.scandir(base):
    print(f"\rProcessing {gitleaks_file.name[:90]:<70}", end="", flush=True)
    if gitleaks_file.is_file():
        with open(gitleaks_file, mode="r", encoding="utf-8") as f:
            entries = json.load(f)
            if len(entries) > 0:
                repo_url = gitleaks_file.name.split("-")[0]
                repo_url = bytes.fromhex(repo_url).decode("utf-8")
                for entry in entries:
                    entry["RepositoryURL"] = repo_url.strip("\n\r\t ")
                    leaks.append(entry)
with open(output, mode="w", encoding="utf-8") as f:
    f.write(json.dumps(leaks))
print("\rDone.%-120s\n" % " ", end="", flush=True)
