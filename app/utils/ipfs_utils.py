import json
import tempfile

import requests

IPFS_API_URL = "http://localhost:5001/api/v0"


def add_file_to_ipfs(file_content):
    with tempfile.NamedTemporaryFile(delete=False) as temp_file:
        temp_file.write(file_content.encode())
        temp_file.flush()
        response = requests.post(
            f"{IPFS_API_URL}/add", files={"file": open(temp_file.name, "rb")}
        )
        response_json = response.json()
        return response_json["Hash"]


def get_file_from_ipfs(cid):
    response = requests.post(f"{IPFS_API_URL}/cat?arg={cid}")
    return response.content


def list_all_files_from_ipfs():
    response = requests.post(f"{IPFS_API_URL}/pin/ls?type=recursive")
    response_json = response.json()
    # print(f"Response: {response_json}")

    # Extract all CIDs except the first one
    cids = list(response_json["Keys"].keys())[1:]

    print(f"Extracted CIDs: {cids}")

    return cids
