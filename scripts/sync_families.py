import json
import urllib.request
import os

# microsoft keeps a json file of the current uf2 families in their repo
# sync it down into the properties file for the extension so we don't have
# to keep editing a massive blob in the code
FAMILIES_URL = (
    "https://raw.githubusercontent.com/microsoft/uf2/master/utils/uf2families.json"
)
OUTPUT_PATH = "src/main/resources/uf2families.properties"


def sync():
    print(f"Fetching families from {FAMILIES_URL}...")
    with urllib.request.urlopen(FAMILIES_URL) as response:
        families = json.loads(response.read().decode())

    os.makedirs(os.path.dirname(OUTPUT_PATH), exist_ok=True)
    with open(OUTPUT_PATH, "w") as f:
        f.write("# UF2 Family IDs synced from microsoft/uf2\n")
        for entry in families:
            family_id = entry["id"]
            # Handle both hex strings and integers
            if isinstance(family_id, str):
                family_id = int(family_id, 16)

            name = entry["short_name"]
            description = entry["description"]
            # Store as ID=NAME|DESCRIPTION
            f.write(f"{family_id:08x}={name}|{description}\n")

    print(f"Successfully synced {len(families)} families to {OUTPUT_PATH}")


if __name__ == "__main__":
    sync()
