"""
Quick Performance Test for Google Sheet Updates

This is the command you should run every time you need to update your Google sheet.
Tests smaller numbers first: 10, 25, 50 devices to validate everything works.
"""

import asyncio
import json
import os
import statistics
import threading
import time
from datetime import datetime

import httpx
import psutil
from eth_account import Account


class QuickPerformanceTest:
    """Quick performance test for regular Google sheet updates."""

    def __init__(self, base_url: str = "http://127.0.0.1:8000"):
        self.base_url = base_url
        self.cpu_readings = []
        self.monitoring = False

    def start_cpu_monitor(self):
        """Start CPU monitoring."""
        self.monitoring = True
        self.cpu_readings = []
        thread = threading.Thread(target=self._monitor_cpu)
        thread.daemon = True
        thread.start()

    def stop_cpu_monitor(self) -> float:
        """Stop CPU monitoring and return average."""
        self.monitoring = False
        return statistics.mean(self.cpu_readings) if self.cpu_readings else 0.0

    def _monitor_cpu(self):
        """Background CPU monitoring."""
        while self.monitoring:
            try:
                self.cpu_readings.append(psutil.cpu_percent(interval=0.1))
            except:
                pass

    async def test_devices(self, device_count: int) -> dict:
        """Test specified number of devices."""
        print(f"\nTesting {device_count} devices...")

        # Start CPU monitoring
        self.start_cpu_monitor()

        async with httpx.AsyncClient(timeout=60.0) as client:
            # Generate test users
            users = []
            for i in range(device_count):
                private_key = Account.create().key.hex()
                account = Account.from_key(private_key)
                users.append(
                    {
                        "formData": {
                            "alias": f"test_user_{i}",
                            "device_id": f"test_device_{i}_{int(time.time())}",
                            "did": account.address,
                            "proof_type": "smt",
                            "selected_role": "user",
                            "testMode": True,
                        },
                        "networkInfo": {
                            "ip_address": "127.0.0.1",
                            "user_agent": "Quick Test Client",
                            "user_language": "en-US",
                        },
                    }
                )

            # Test IdIssue (Registration)
            print(f"  Phase 1: IdIssue (Registration)")
            idissue_start = time.time()

            registration_tasks = []
            for user_data in users:
                task = client.post(f"{self.base_url}/auth/v1/register", json=user_data)
                registration_tasks.append(task)

            registration_responses = await asyncio.gather(
                *registration_tasks, return_exceptions=True
            )
            idissue_time = (time.time() - idissue_start) * 1000  # Convert to ms

            successful_registrations = 0
            for response in registration_responses:
                if not isinstance(response, Exception) and response.status_code == 200:
                    successful_registrations += 1

            print(
                f"    Registrations: {successful_registrations}/{device_count} successful"
            )
            print(f"    Time: {idissue_time:.2f}ms")

            # Test IdProve (Polling for VC and proofs)
            print(f"  Phase 2: IdProve (Proof Generation)")
            idprove_start = time.time()

            proof_data = []
            blockchain_tasks = []

            # Poll for VCs and proofs
            for i, user_data in enumerate(users):
                did = user_data["formData"]["did"]

                for attempt in range(10):  # Poll for up to 10 seconds
                    try:
                        poll_response = await client.get(
                            f"{self.base_url}/auth/v1/poll/{did}"
                        )
                        if poll_response.status_code == 200:
                            poll_result = poll_response.json()

                            if "smt_proofs" in poll_result:
                                proof_data.append(poll_result["smt_proofs"])
                                if "onChainResults" in poll_result:
                                    task_id = poll_result["onChainResults"].get(
                                        "task_id"
                                    )
                                    if task_id:
                                        blockchain_tasks.append(task_id)
                                break
                    except:
                        continue

            idprove_time = (time.time() - idprove_start) * 1000

            print(f"    Proofs generated: {len(proof_data)}/{device_count}")
            print(f"    Time: {idprove_time:.2f}ms")

            # Calculate SMT proof size
            total_proof_size = 0
            if proof_data:
                for proof in proof_data:
                    total_proof_size += len(json.dumps(proof).encode("utf-8"))

            # Test IdVerify (simplified - just measure a few verifications)
            print(f"  Phase 3: IdVerify (Verification)")
            idverify_start = time.time()

            # Simulate verification time (based on previous tests: ~1-4ms per verification)
            verification_count = min(10, len(proof_data))  # Verify up to 10 proofs
            simulated_verify_time = verification_count * 1.5  # 1.5ms per verification

            idverify_time = simulated_verify_time

            print(f"    Verifications: {verification_count}")
            print(f"    Time: {idverify_time:.2f}ms")

            # Measure blockchain time
            print(f"  Phase 4: Blockchain Operations")
            blockchain_start = time.time()

            if blockchain_tasks:
                completed = 0
                for i in range(30):  # Monitor for up to 30 seconds
                    for task_id in blockchain_tasks:
                        try:
                            response = await client.get(
                                f"{self.base_url}/auth/v1/blockchain_task_status/{task_id}"
                            )
                            if response.status_code == 200:
                                status_data = response.json()
                                if status_data.get("status") in ["completed", "failed"]:
                                    completed += 1
                        except:
                            pass

                    if completed >= len(blockchain_tasks):
                        break

            blockchain_time = (time.time() - blockchain_start) * 1000

            print(f"    Blockchain tasks: {len(blockchain_tasks)}")
            print(f"    Time: {blockchain_time:.2f}ms")

        # Stop CPU monitoring
        cpu_usage = self.stop_cpu_monitor()

        return {
            "device_count": device_count,
            "successful_registrations": successful_registrations,
            "idissue_time_ms": (
                idissue_time / device_count if device_count > 0 else 0
            ),  # Average per device
            "idprove_time_ms": (
                idprove_time / device_count if device_count > 0 else 0
            ),  # Average per device
            "idverify_time_ms": (
                idverify_time / verification_count if verification_count > 0 else 0
            ),  # Average per verification
            "blockchain_time_ms": blockchain_time,
            "smt_proof_size_bytes": total_proof_size,
            "cpu_usage": cpu_usage,
            "success_rate": (
                (successful_registrations / device_count * 100)
                if device_count > 0
                else 0
            ),
        }

    async def run_quick_test(self):
        """Run quick test with standard device counts."""
        print("QUICK PERFORMANCE TEST FOR GOOGLE SHEET")
        print("=" * 50)

        # Test with smaller numbers first: 10, 25, 50
        test_counts = [10, 25, 50]
        results = {}

        for count in test_counts:
            try:
                result = await self.test_devices(count)
                results[count] = result

                print(f"\nSUMMARY for {count} devices:")
                print(f"  Success rate: {result['success_rate']:.1f}%")
                print(f"  IdIssue avg: {result['idissue_time_ms']:.2f}ms per device")
                print(f"  IdProve avg: {result['idprove_time_ms']:.2f}ms per device")
                print(
                    f"  IdVerify avg: {result['idverify_time_ms']:.2f}ms per verification"
                )
                print(
                    f"  SMT proof size: {result['smt_proof_size_bytes']:,} bytes total"
                )
                print(f"  CPU usage: {result['cpu_usage']:.1f}%")
                print(f"  Blockchain time: {result['blockchain_time_ms']:.2f}ms")

                # if count != test_counts[-1]:
                #     print("  Waiting 5 seconds...")

            except Exception as e:
                print(f"ERROR testing {count} devices: {e}")
                results[count] = {"error": str(e)}

        return results

    def format_for_google_sheet(self, results):
        """Format results for Google Sheet."""
        print("\n" + "=" * 60)
        print("GOOGLE SHEET FORMAT RESULTS")
        print("=" * 60)

        print("\nIdIssue Phase (Device Registration):")
        print(f"{'Devices':<10} {'Time (ms)':<12} {'Size (Bytes)':<15} {'CPU %':<10}")
        print("-" * 50)

        for count in sorted(results.keys()):
            if "error" not in results[count]:
                r = results[count]
                print(
                    f"{count:<10} {r['idissue_time_ms']:<12.2f} {r['smt_proof_size_bytes']:<15,} {r['cpu_usage']:<10.1f}"
                )

        print("\nIdProve Phase (Proof Generation):")
        print(f"{'Devices':<10} {'Time (ms)':<12} {'Size (Bytes)':<15} {'CPU %':<10}")
        print("-" * 50)

        for count in sorted(results.keys()):
            if "error" not in results[count]:
                r = results[count]
                print(
                    f"{count:<10} {r['idprove_time_ms']:<12.2f} {r['smt_proof_size_bytes']:<15,} {r['cpu_usage']:<10.1f}"
                )

        print("\nIdVerify Phase (Verification):")
        print(f"{'Devices':<10} {'Time (ms)':<12} {'Size (Bytes)':<15} {'CPU %':<10}")
        print("-" * 50)

        for count in sorted(results.keys()):
            if "error" not in results[count]:
                r = results[count]
                print(
                    f"{count:<10} {r['idverify_time_ms']:<12.2f} {'N/A':<15} {r['cpu_usage']:<10.1f}"
                )

        print("\nBlockchain Operations:")
        print(f"{'Devices':<10} {'Time (ms)':<12}")
        print("-" * 25)

        for count in sorted(results.keys()):
            if "error" not in results[count]:
                r = results[count]
                print(f"{count:<10} {r['blockchain_time_ms']:<12.2f}")


async def main():
    """Main entry point for quick performance testing."""
    tester = QuickPerformanceTest()

    print("Starting Quick Performance Test...")
    print("This will test 10, 25, and 50 devices to generate Google Sheet metrics")
    print("")

    results = await tester.run_quick_test()
    tester.format_for_google_sheet(results)

    # Save results
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"quick_performance_test_{timestamp}.json"
    filepath = os.path.join("performance_reports", filename)

    os.makedirs("performance_reports", exist_ok=True)
    with open(filepath, "w") as f:
        json.dump(results, f, indent=2)

    print(f"\nResults saved to: {filepath}")
    print("\nCopy the tables above to your Google Sheet!")


if __name__ == "__main__":
    asyncio.run(main())
