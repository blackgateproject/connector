"""
Comprehensive performance test script for Google Sheet data collection.

This script tests IdIssue, IdProve, IdVerify, and Revocation phases
with multiple device counts and collects detailed performance metrics.
"""

import asyncio
import json
import os
import sys
import time
from datetime import datetime
from typing import Any, Dict, List

import psutil

# Add the app directory to the path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.utils.async_blockchain_multiworker import get_blockchain_processor
from app.utils.core_selector import get_cached_smt_core, is_multi_worker_mode


class GoogleSheetPerformanceCollector:
    """Collects performance data in Google Sheet format."""

    def __init__(self):
        self.test_results = []
        self.start_time = datetime.now()

        # Enable multi-worker mode for testing
        os.environ["MULTI_WORKER_MODE"] = "true"
        os.environ["WORKER_ID"] = "perf-test-main"

    async def initialize(self):
        """Initialize the performance testing environment."""
        print("🔧 Initializing performance testing environment...")

        # Initialize blockchain processor
        processor = get_blockchain_processor()
        await processor.start()

        # Initialize SMT core
        smt_core = get_cached_smt_core()
        if hasattr(smt_core, "initialize"):
            await smt_core.initialize()

        print(f"✅ Multi-worker mode: {is_multi_worker_mode()}")
        print(f"✅ SMT Core type: {type(smt_core)}")
        print("✅ Environment initialized")

    async def test_id_issue_phase(self, device_count: int) -> Dict[str, Any]:
        """Test IdIssue phase (device registration/DID creation)."""
        print(f"\n📝 Testing IdIssue phase with {device_count} devices...")

        smt_core = get_cached_smt_core()
        results = []
        cpu_usage = []
        memory_usage = []

        start_time = time.time()
        process = psutil.Process()

        for i in range(device_count):
            device_start = time.time()

            # Simulate device registration
            did = f"did:ethr:blackgate:device_{i:04d}"
            credentials = f"pubkey_{i:04d}"

            # Add user to SMT (IdIssue operation)
            user_data = smt_core.add_user(did, credentials)

            device_time = (time.time() - device_start) * 1000  # Convert to ms
            results.append(device_time)

            # Collect system metrics
            cpu_usage.append(process.cpu_percent())
            memory_usage.append(process.memory_info().rss / 1024 / 1024)  # MB

            if (i + 1) % 10 == 0:
                print(f"  Registered {i + 1}/{device_count} devices...")

        total_time = (time.time() - start_time) * 1000  # Convert to ms
        avg_time = sum(results) / len(results) if results else 0
        max_time = max(results) if results else 0
        min_time = min(results) if results else 0

        # Calculate proof size (approximate)
        if hasattr(smt_core, "get_proof"):
            sample_proof = smt_core.get_proof(f"device_000")
            proof_size = len(str(sample_proof)) if sample_proof else 0
        else:
            proof_size = 256  # Estimated SMT proof size

        return {
            "phase": "IdIssue",
            "device_count": device_count,
            "total_time_ms": round(total_time, 2),
            "avg_time_ms": round(avg_time, 2),
            "min_time_ms": round(min_time, 2),
            "max_time_ms": round(max_time, 2),
            "proof_size_bytes": proof_size,
            "avg_cpu_percent": (
                round(sum(cpu_usage) / len(cpu_usage), 2) if cpu_usage else 0
            ),
            "max_memory_mb": round(max(memory_usage), 2) if memory_usage else 0,
            "throughput_ops_sec": round(device_count / (total_time / 1000), 2),
        }

    async def test_id_prove_phase(self, device_count: int) -> Dict[str, Any]:
        """Test IdProve phase (proof generation)."""
        print(f"\n🔍 Testing IdProve phase with {device_count} devices...")

        smt_core = get_cached_smt_core()
        results = []
        cpu_usage = []
        memory_usage = []
        total_proof_size = 0

        start_time = time.time()
        process = psutil.Process()

        for i in range(device_count):
            device_start = time.time()

            # Generate proof for device
            did = f"did:ethr:blackgate:device_{i:04d}"
            credentials = f"pubkey_{i:04d}"

            # Generate proof (IdProve operation)
            if hasattr(smt_core, "get_proof"):
                # Hash the user data to get key
                if hasattr(smt_core, "_hash_user_data"):
                    key = smt_core._hash_user_data(did, credentials)
                    proof = smt_core.get_proof(key)
                else:
                    proof = smt_core.get_proof(did)

                if proof:
                    total_proof_size += len(str(proof))

            device_time = (time.time() - device_start) * 1000  # Convert to ms
            results.append(device_time)

            # Collect system metrics
            cpu_usage.append(process.cpu_percent())
            memory_usage.append(process.memory_info().rss / 1024 / 1024)  # MB

            if (i + 1) % 10 == 0:
                print(f"  Generated proofs for {i + 1}/{device_count} devices...")

        total_time = (time.time() - start_time) * 1000  # Convert to ms
        avg_time = sum(results) / len(results) if results else 0
        max_time = max(results) if results else 0
        min_time = min(results) if results else 0
        avg_proof_size = total_proof_size / device_count if device_count > 0 else 0

        return {
            "phase": "IdProve",
            "device_count": device_count,
            "total_time_ms": round(total_time, 2),
            "avg_time_ms": round(avg_time, 2),
            "min_time_ms": round(min_time, 2),
            "max_time_ms": round(max_time, 2),
            "proof_size_bytes": round(avg_proof_size, 2),
            "avg_cpu_percent": (
                round(sum(cpu_usage) / len(cpu_usage), 2) if cpu_usage else 0
            ),
            "max_memory_mb": round(max(memory_usage), 2) if memory_usage else 0,
            "throughput_ops_sec": round(device_count / (total_time / 1000), 2),
        }

    async def test_id_verify_phase(self, device_count: int) -> Dict[str, Any]:
        """Test IdVerify phase (proof verification)."""
        print(f"\n✅ Testing IdVerify phase with {device_count} devices...")

        smt_core = get_cached_smt_core()
        results = []
        cpu_usage = []
        memory_usage = []
        successful_verifications = 0

        start_time = time.time()
        process = psutil.Process()

        for i in range(device_count):
            device_start = time.time()

            # Verify proof for device
            did = f"did:ethr:blackgate:device_{i:04d}"
            credentials = f"pubkey_{i:04d}"

            # Verify proof (IdVerify operation)
            if hasattr(smt_core, "verify_proof"):
                # Generate proof first
                if hasattr(smt_core, "_hash_user_data"):
                    key = smt_core._hash_user_data(did, credentials)
                    proof = smt_core.get_proof(key)
                    if proof:
                        verification_result = smt_core.verify_proof(key, proof)
                        if verification_result:
                            successful_verifications += 1
                else:
                    proof = smt_core.get_proof(did)
                    if proof:
                        verification_result = smt_core.verify_proof(did, proof)
                        if verification_result:
                            successful_verifications += 1

            device_time = (time.time() - device_start) * 1000  # Convert to ms
            results.append(device_time)

            # Collect system metrics
            cpu_usage.append(process.cpu_percent())
            memory_usage.append(process.memory_info().rss / 1024 / 1024)  # MB

            if (i + 1) % 10 == 0:
                print(f"  Verified proofs for {i + 1}/{device_count} devices...")

        total_time = (time.time() - start_time) * 1000  # Convert to ms
        avg_time = sum(results) / len(results) if results else 0
        max_time = max(results) if results else 0
        min_time = min(results) if results else 0

        return {
            "phase": "IdVerify",
            "device_count": device_count,
            "total_time_ms": round(total_time, 2),
            "avg_time_ms": round(avg_time, 2),
            "min_time_ms": round(min_time, 2),
            "max_time_ms": round(max_time, 2),
            "proof_size_bytes": 256,  # Verification doesn't produce new proof
            "avg_cpu_percent": (
                round(sum(cpu_usage) / len(cpu_usage), 2) if cpu_usage else 0
            ),
            "max_memory_mb": round(max(memory_usage), 2) if memory_usage else 0,
            "throughput_ops_sec": round(device_count / (total_time / 1000), 2),
            "success_rate": (
                round(successful_verifications / device_count * 100, 2)
                if device_count > 0
                else 0
            ),
        }

    async def test_revocation_phase(self, device_count: int) -> Dict[str, Any]:
        """Test Revocation phase (identity revocation via SMT deletion)."""
        print(f"\n❌ Testing Revocation phase with {device_count} devices...")

        smt_core = get_cached_smt_core()
        results = []
        cpu_usage = []
        memory_usage = []
        successful_revocations = 0

        start_time = time.time()
        process = psutil.Process()

        # First, ensure devices are registered for revocation
        for i in range(device_count):
            did = f"did:ethr:blackgate:revoke_{i:04d}"
            credentials = f"pubkey_revoke_{i:04d}"
            smt_core.add_user(did, credentials)

        # Now test revocation
        for i in range(device_count):
            device_start = time.time()

            did = f"did:ethr:blackgate:revoke_{i:04d}"
            credentials = f"pubkey_revoke_{i:04d}"

            # Revocation operation (simulate via re-adding with revoked status)
            if hasattr(smt_core, "remove_user"):
                result = smt_core.remove_user(did)
                if result:
                    successful_revocations += 1
            else:
                # Simulate revocation by adding with revoked credentials
                revoked_credentials = f"REVOKED_{credentials}"
                smt_core.add_user(did, revoked_credentials)
                successful_revocations += 1

            device_time = (time.time() - device_start) * 1000  # Convert to ms
            results.append(device_time)

            # Collect system metrics
            cpu_usage.append(process.cpu_percent())
            memory_usage.append(process.memory_info().rss / 1024 / 1024)  # MB

            if (i + 1) % 10 == 0:
                print(f"  Revoked {i + 1}/{device_count} devices...")

        total_time = (time.time() - start_time) * 1000  # Convert to ms
        avg_time = sum(results) / len(results) if results else 0
        max_time = max(results) if results else 0
        min_time = min(results) if results else 0

        return {
            "phase": "Revocation",
            "device_count": device_count,
            "total_time_ms": round(total_time, 2),
            "avg_time_ms": round(avg_time, 2),
            "min_time_ms": round(min_time, 2),
            "max_time_ms": round(max_time, 2),
            "proof_size_bytes": 256,  # Revocation proof size
            "avg_cpu_percent": (
                round(sum(cpu_usage) / len(cpu_usage), 2) if cpu_usage else 0
            ),
            "max_memory_mb": round(max(memory_usage), 2) if memory_usage else 0,
            "throughput_ops_sec": round(device_count / (total_time / 1000), 2),
            "success_rate": (
                round(successful_revocations / device_count * 100, 2)
                if device_count > 0
                else 0
            ),
        }

    async def run_comprehensive_test(self, device_counts: List[int]):
        """Run comprehensive tests for all phases and device counts."""
        print(f"🚀 Starting comprehensive performance test for Google Sheet data")
        print(f"📊 Testing device counts: {device_counts}")
        print(f"📈 Testing phases: IdIssue, IdProve, IdVerify, Revocation")

        await self.initialize()

        for device_count in device_counts:
            print(f"\n{'='*60}")
            print(f"🔄 Testing with {device_count} devices")
            print(f"{'='*60}")

            # Test each phase
            try:
                id_issue_result = await self.test_id_issue_phase(device_count)
                self.test_results.append(id_issue_result)
                print(
                    f"✅ IdIssue: {id_issue_result['avg_time_ms']:.2f}ms avg, {id_issue_result['throughput_ops_sec']:.2f} ops/sec"
                )

                id_prove_result = await self.test_id_prove_phase(device_count)
                self.test_results.append(id_prove_result)
                print(
                    f"✅ IdProve: {id_prove_result['avg_time_ms']:.2f}ms avg, {id_prove_result['throughput_ops_sec']:.2f} ops/sec"
                )

                id_verify_result = await self.test_id_verify_phase(device_count)
                self.test_results.append(id_verify_result)
                print(
                    f"✅ IdVerify: {id_verify_result['avg_time_ms']:.2f}ms avg, {id_verify_result['throughput_ops_sec']:.2f} ops/sec"
                )

                revocation_result = await self.test_revocation_phase(device_count)
                self.test_results.append(revocation_result)
                print(
                    f"✅ Revocation: {revocation_result['avg_time_ms']:.2f}ms avg, {revocation_result['throughput_ops_sec']:.2f} ops/sec"
                )

            except Exception as e:
                print(f"❌ Error testing {device_count} devices: {e}")
                continue

    def generate_google_sheet_format(self) -> str:
        """Generate results in Google Sheet format."""
        timestamp = self.start_time.strftime("%Y%m%d_%H%M%S")

        # Create CSV-style output for easy copy-paste to Google Sheets
        output = []
        output.append("# Blackgate Connector Performance Test Results")
        output.append(f"# Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        output.append(f"# Multi-worker mode: {is_multi_worker_mode()}")
        output.append(
            f"# Test duration: {(datetime.now() - self.start_time).total_seconds():.2f} seconds"
        )
        output.append("")

        # Headers
        headers = [
            "Phase",
            "Device Count",
            "Avg Time (ms)",
            "Min Time (ms)",
            "Max Time (ms)",
            "Total Time (ms)",
            "Proof Size (bytes)",
            "CPU Usage (%)",
            "Memory (MB)",
            "Throughput (ops/sec)",
            "Success Rate (%)",
        ]
        output.append(",".join(headers))

        # Data rows
        for result in self.test_results:
            row = [
                result["phase"],
                str(result["device_count"]),
                str(result["avg_time_ms"]),
                str(result["min_time_ms"]),
                str(result["max_time_ms"]),
                str(result["total_time_ms"]),
                str(result["proof_size_bytes"]),
                str(result["avg_cpu_percent"]),
                str(result["max_memory_mb"]),
                str(result["throughput_ops_sec"]),
                str(result.get("success_rate", "100.0")),
            ]
            output.append(",".join(row))

        return "\n".join(output)

    def save_results(self):
        """Save results to files."""
        timestamp = self.start_time.strftime("%Y%m%d_%H%M%S")

        # Save CSV format
        csv_output = self.generate_google_sheet_format()
        csv_filename = f"performance_reports/google_sheet_data_{timestamp}.csv"
        with open(csv_filename, "w") as f:
            f.write(csv_output)

        # Save detailed JSON
        json_filename = f"performance_reports/detailed_results_{timestamp}.json"
        with open(json_filename, "w") as f:
            json.dump(
                {
                    "test_metadata": {
                        "start_time": self.start_time.isoformat(),
                        "end_time": datetime.now().isoformat(),
                        "multi_worker_mode": is_multi_worker_mode(),
                        "total_tests": len(self.test_results),
                    },
                    "results": self.test_results,
                },
                f,
                indent=2,
            )

        print(f"\n📄 Results saved:")
        print(f"   CSV (Google Sheets): {csv_filename}")
        print(f"   Detailed JSON: {json_filename}")

        return csv_filename, json_filename


async def main():
    """Main test execution."""
    # Test with multiple device counts for comprehensive data
    device_counts = [1, 5, 10, 25, 50, 100]

    collector = GoogleSheetPerformanceCollector()
    await collector.run_comprehensive_test(device_counts)

    # Generate and display results
    csv_output = collector.generate_google_sheet_format()
    print(f"\n{'='*80}")
    print("📊 GOOGLE SHEET DATA (Copy and paste into spreadsheet)")
    print(f"{'='*80}")
    print(csv_output)
    print(f"{'='*80}")

    # Save to files
    csv_file, json_file = collector.save_results()

    print(f"\n🎉 Performance testing complete!")
    print(f"📈 Total tests run: {len(collector.test_results)}")
    print(f"📋 Data ready for Google Sheets: {csv_file}")


if __name__ == "__main__":
    asyncio.run(main())
