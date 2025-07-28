"""
Automated Load Test Runner for Blackgate Connector

This script runs parallel performance tests for the specified load levels:
100, 200, 400, 800, and 1000 users.
"""

import argparse
import asyncio
import json
import os
import sys
from datetime import datetime
from typing import List

# Add the parent directory to the path to import app modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from performance_testing.load_test_framework import (
    LoadTestResult,
    LoadTestRunner,
    generate_load_test_report,
)


class AutomatedLoadTestSuite:
    """Automated test suite that runs multiple load levels."""

    def __init__(self, base_url: str = "http://localhost:8000", db_url: str = None):
        self.runner = LoadTestRunner(base_url, db_url)
        self.results: List[LoadTestResult] = []

    async def run_all_load_levels(
        self, custom_levels: List[int] = None
    ) -> List[LoadTestResult]:
        """Run tests for all specified load levels."""
        load_levels = custom_levels or [100, 200, 400, 800, 1000]

        print(f"🚀 Starting automated load test suite for levels: {load_levels}")
        print(f"🔗 Target URL: {self.runner.client.base_url}")
        print("=" * 80)

        all_results = []

        for level in load_levels:
            print(f"\n📊 Running load test for {level} users...")
            print(f"⏰ Started at: {datetime.now().strftime('%H:%M:%S')}")

            try:
                # Adjust concurrency based on load level
                max_concurrent = min(50, level // 2) if level > 100 else 20

                result = await self.runner.run_load_test(
                    num_users=level, max_concurrent=max_concurrent
                )

                all_results.append(result)

                # Print immediate results
                print(f"✅ Completed {level} users test:")
                print(
                    f"   Success Rate: {(result.successful_users/result.total_users)*100:.1f}%"
                )
                print(f"   Duration: {result.test_duration:.1f}s")
                print(f"   Throughput: {result.throughput_per_second:.2f} users/sec")
                print(f"   Avg Total Time: {result.avg_total_time:.2f}s")

                if result.failed_users > 0:
                    print(f"⚠️  {result.failed_users} users failed")

            except Exception as e:
                print(f"❌ Failed to run {level} users test: {str(e)}")
                continue

        self.results = all_results
        return all_results

    def generate_comprehensive_report(
        self, output_dir: str = "performance_reports"
    ) -> str:
        """Generate a comprehensive report for all test runs."""
        if not self.results:
            return "No test results available"

        # Create output directory
        os.makedirs(output_dir, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        # Generate individual reports
        report_files = []
        for i, result in enumerate(self.results):
            filename = (
                f"{output_dir}/load_test_{result.total_users}_users_{timestamp}.md"
            )
            generate_load_test_report(result, filename)
            report_files.append(filename)

        # Generate comprehensive summary
        summary_file = f"{output_dir}/load_test_summary_{timestamp}.md"
        summary_report = self._generate_summary_report()

        with open(summary_file, "w", encoding="utf-8") as f:
            f.write(summary_report)

        # Generate JSON data for further analysis
        json_file = f"{output_dir}/load_test_data_{timestamp}.json"
        self._export_json_data(json_file)

        print(f"\n📋 Reports generated:")
        print(f"   Summary: {summary_file}")
        print(f"   JSON Data: {json_file}")
        for report_file in report_files:
            print(f"   Individual: {report_file}")

        return summary_file

    def _generate_summary_report(self) -> str:
        """Generate a summary report comparing all load levels."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        report = f"""# Load Test Summary Report - {timestamp}

## Overview
This report summarizes parallel performance tests across multiple load levels for the Blackgate Connector registration and verification process.

## Test Configuration
- **Target URL**: {self.runner.client.base_url}
- **Load Levels Tested**: {[r.total_users for r in self.results]}
- **Total Tests**: {len(self.results)}

## Summary Results

| Users | Success Rate | Throughput (u/s) | Avg Total Time (s) | 95th Percentile (s) | Duration (s) |
|-------|--------------|------------------|-------------------|-------------------|--------------|"""

        for result in self.results:
            success_rate = (result.successful_users / result.total_users) * 100
            report += f"\n| {result.total_users} | {success_rate:.1f}% | {result.throughput_per_second:.2f} | {result.avg_total_time:.2f} | {result.percentile_95_time:.2f} | {result.test_duration:.1f} |"

        # Performance analysis
        report += "\n\n## Performance Analysis\n"

        if len(self.results) > 1:
            # Calculate scalability metrics
            throughputs = [r.throughput_per_second for r in self.results]
            load_levels = [r.total_users for r in self.results]

            report += f"### Scalability Metrics\n"
            report += f"- **Peak Throughput**: {max(throughputs):.2f} users/second at {load_levels[throughputs.index(max(throughputs))]} users\n"
            report += f"- **Throughput Range**: {min(throughputs):.2f} - {max(throughputs):.2f} users/second\n"

            # Success rate analysis
            success_rates = [
                (r.successful_users / r.total_users) * 100 for r in self.results
            ]
            report += f"- **Success Rate Range**: {min(success_rates):.1f}% - {max(success_rates):.1f}%\n"

            # Response time analysis
            avg_times = [r.avg_total_time for r in self.results]
            report += f"- **Response Time Range**: {min(avg_times):.2f}s - {max(avg_times):.2f}s\n"

        # Detailed timing breakdown
        report += "\n### Detailed Timing Breakdown (Average across all successful requests)\n\n"
        report += "| Load Level | Wallet Gen | Wallet Enc | Network Info | SMT Local | VC Issuance | SMT Onchain | VP Gen |\n"
        report += "|------------|------------|------------|--------------|-----------|-------------|-------------|--------|\n"

        for result in self.results:
            if result.successful_users > 0:
                successful_metrics = [m for m in result.user_metrics if m.success]
                avg_wallet_gen = sum(
                    m.wallet_gen_time for m in successful_metrics
                ) / len(successful_metrics)
                avg_wallet_enc = sum(
                    m.wallet_enc_time for m in successful_metrics
                ) / len(successful_metrics)
                avg_network_info = sum(
                    m.network_info_time for m in successful_metrics
                ) / len(successful_metrics)
                avg_smt_local = sum(
                    m.smt_local_add_time for m in successful_metrics
                ) / len(successful_metrics)
                avg_vc_issuance = sum(
                    m.vc_issuance_time for m in successful_metrics
                ) / len(successful_metrics)
                avg_smt_onchain = sum(
                    m.smt_onchain_add_time for m in successful_metrics
                ) / len(successful_metrics)
                avg_vp_gen = sum(m.vp_gen_time for m in successful_metrics) / len(
                    successful_metrics
                )

                report += f"| {result.total_users} | {avg_wallet_gen:.4f}s | {avg_wallet_enc:.4f}s | {avg_network_info:.4f}s | {avg_smt_local:.4f}s | {avg_vc_issuance:.4f}s | {avg_smt_onchain:.4f}s | {avg_vp_gen:.4f}s |\n"

        # Error analysis
        if any(result.errors for result in self.results):
            report += "\n### Error Analysis\n"
            all_errors = []
            for result in self.results:
                all_errors.extend(result.errors)

            error_counts = {}
            for error in all_errors:
                error_type = error.split(":")[0] if ":" in error else "Unknown"
                error_counts[error_type] = error_counts.get(error_type, 0) + 1

            for error_type, count in error_counts.items():
                report += f"- **{error_type}**: {count} total occurrences\n"

        # Recommendations
        report += "\n## Recommendations\n"

        if self.results:
            max_success_rate = max(
                (r.successful_users / r.total_users) * 100 for r in self.results
            )
            min_success_rate = min(
                (r.successful_users / r.total_users) * 100 for r in self.results
            )

            if max_success_rate < 95:
                report += "- ⚠️ Success rates below 95% indicate potential system bottlenecks\n"

            if min_success_rate < 90:
                report += "- 🔴 Success rates below 90% suggest system instability under load\n"

            max_throughput = max(r.throughput_per_second for r in self.results)
            optimal_load = [
                r.total_users
                for r in self.results
                if r.throughput_per_second == max_throughput
            ][0]
            report += f"- 🎯 Optimal load level appears to be around {optimal_load} users (peak throughput)\n"

            if any(r.avg_total_time > 30 for r in self.results):
                report += (
                    "- ⏰ Response times over 30 seconds may impact user experience\n"
                )

        return report

    def _export_json_data(self, filename: str):
        """Export test data as JSON for further analysis."""
        data = {
            "timestamp": datetime.now().isoformat(),
            "test_summary": {
                "total_tests": len(self.results),
                "load_levels": [r.total_users for r in self.results],
                "base_url": self.runner.client.base_url,
            },
            "results": [],
        }

        for result in self.results:
            result_data = {
                "load_level": result.total_users,
                "successful_users": result.successful_users,
                "failed_users": result.failed_users,
                "test_duration": result.test_duration,
                "avg_registration_time": result.avg_registration_time,
                "avg_verification_time": result.avg_verification_time,
                "avg_total_time": result.avg_total_time,
                "min_total_time": result.min_total_time,
                "max_total_time": result.max_total_time,
                "percentile_95_time": result.percentile_95_time,
                "percentile_99_time": result.percentile_99_time,
                "throughput_per_second": result.throughput_per_second,
                "error_rate": result.error_rate,
                "user_metrics": [
                    {
                        "did_str": m.did_str,
                        "wallet_gen_time": m.wallet_gen_time,
                        "wallet_enc_time": m.wallet_enc_time,
                        "network_info_time": m.network_info_time,
                        "smt_local_add_time": m.smt_local_add_time,
                        "vc_issuance_time": m.vc_issuance_time,
                        "smt_onchain_add_time": m.smt_onchain_add_time,
                        "vp_gen_time": m.vp_gen_time,
                        "client_register_total_time": m.client_register_total_time,
                        "total_process_time": m.total_process_time,
                        "success": m.success,
                        "error_message": m.error_message,
                    }
                    for m in result.user_metrics
                ],
            }
            data["results"].append(result_data)

        with open(filename, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)


async def main():
    """Main entry point for the automated load test suite."""
    parser = argparse.ArgumentParser(
        description="Run automated load tests for Blackgate Connector"
    )
    parser.add_argument(
        "--url", default="http://localhost:8000", help="Base URL for the connector API"
    )
    parser.add_argument("--db-url", help="PostgreSQL database URL for storing metrics")
    parser.add_argument(
        "--levels",
        nargs="+",
        type=int,
        default=[100, 200, 400, 800, 1000],
        help="Load levels to test (default: 100 200 400 800 1000)",
    )
    parser.add_argument(
        "--output-dir",
        default="performance_reports",
        help="Output directory for reports",
    )
    parser.add_argument(
        "--single-level", type=int, help="Run only a single load level test"
    )

    args = parser.parse_args()

    print("🔧 Blackgate Connector - Automated Load Test Suite")
    print("=" * 80)

    # Initialize test suite
    suite = AutomatedLoadTestSuite(args.url, args.db_url)

    try:
        if args.single_level:
            # Run single load level
            print(f"Running single load test for {args.single_level} users...")
            result = await suite.runner.run_load_test(args.single_level)
            suite.results = [result]
        else:
            # Run all load levels
            await suite.run_all_load_levels(args.levels)

        # Generate reports
        if suite.results:
            summary_file = suite.generate_comprehensive_report(args.output_dir)
            print(f"\n✅ All tests completed successfully!")
            print(f"📊 Summary report: {summary_file}")
        else:
            print("\n❌ No successful test runs to report")

    except KeyboardInterrupt:
        print("\n⏹️ Tests interrupted by user")
    except Exception as e:
        print(f"\n❌ Test suite failed: {str(e)}")
        raise


if __name__ == "__main__":
    asyncio.run(main())
