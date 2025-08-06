import asyncio

import httpx
from eth_account import Account


async def test_single_registration_and_poll():
    private_key = Account.create().key.hex()
    account = Account.from_key(private_key)

    user_data = {
        "formData": {
            "alias": "test_smt_proof",
            "device_id": f'test_device_{int(__import__("time").time())}',
            "did": account.address,
            "proof_type": "smt",
            "selected_role": "user",
            "testMode": True,
        },
        "networkInfo": {
            "ip_address": "127.0.0.1",
            "user_agent": "Test Client",
            "user_language": "en-US",
        },
    }

    async with httpx.AsyncClient(timeout=60.0) as client:
        # Register
        print(f"Registering DID: {account.address}")
        response = await client.post(
            "http://127.0.0.1:8000/auth/v1/register", json=user_data
        )
        print(f"Registration status: {response.status_code}")

        # Poll for SMT proofs
        print(f"Polling for DID: {account.address}")
        poll_response = await client.get(
            f"http://127.0.0.1:8000/auth/v1/poll/{account.address}"
        )
        print(f"Poll status: {poll_response.status_code}")

        if poll_response.status_code == 200:
            poll_data = poll_response.json()
            print(f"Poll response keys: {list(poll_data.keys())}")
            if "smt_proofs" in poll_data:
                print(f'SMT proofs found: {type(poll_data.get("smt_proofs"))}')
                print(f'SMT proof structure: {poll_data.get("smt_proofs")}')
            else:
                print("No smt_proofs in response")


if __name__ == "__main__":
    asyncio.run(test_single_registration_and_poll())
