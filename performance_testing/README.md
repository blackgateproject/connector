# Performance Testing Documentation

This directory contains a comprehensive parallel performance testing framework for the Blackgate Connector, specifically designed to test the end-to-end registration and verification process for multiple users concurrently.

## Overview

The framework measures detailed timing metrics for each registered `did_str` across all relevant steps as defined in the `times_of_time` PostgreSQL table, including:

- `wallet_gen_time` - Time to generate wallet
- `wallet_enc_time` - Time to encrypt wallet
- `network_info_time` - Time to gather network information
- `smt_local_add_time` - Time to add user to local SMT
- `vc_issuance_time` - Time for VC issuance
- `smt_onchain_add_time` - Time to add user to onchain SMT
- `vp_gen_time` - Time to generate VP
- `client_register_total_time` - Total client registration time
- `vp_verify_time` - Time to verify VP
- `vc_verify_time` - Time to verify VC
- `smt_local_verify_time` - Time for local SMT verification
- `smt_onchain_verify_time` - Time for onchain SMT verification
- `smt_proof_gen_time` - Time for SMT proof generation
- `smt_on_server_verify_time` - Time for server-side SMT verification
- `smt_total_verify_time` - Total SMT verification time

## Framework Components

### Core Files

- **`load_test_framework.py`** - Main framework with load testing classes
- **`run_load_tests.py`** - Automated test runner for all load levels
- **`individual_tests.py`** - Standalone scripts for specific user counts
- **`config.py`** - Configuration management and utilities
- **`conftest.py`** - PyTest configuration and fixtures
- **`test_performance.py`** - PyTest test cases

### Support Files

- **`requirements-perf.txt`** - Additional dependencies for performance testing
- **`README.md`** - This documentation file

## Quick Start

### 1. Install Dependencies

```bash
# Install performance testing dependencies
pip install -r performance_testing/requirements-perf.txt
```

### 2. Configure Environment

Set environment variables (optional):

```bash
export PERF_TEST_BASE_URL="http://localhost:8000"
export PERF_TEST_DB_URL="postgresql://username:password@localhost:5432/database"
export PERF_TEST_OUTPUT_DIR="performance_reports"
```

### 3. Run Load Tests

#### Run All Load Levels (100, 200, 400, 800, 1000 users)

```bash
# Run complete automated test suite
python performance_testing/run_load_tests.py

# With custom parameters
python performance_testing/run_load_tests.py --url http://localhost:8000 --db-url "postgresql://..." --output-dir ./reports
```

#### Run Specific Load Level

```bash
# Run single load level
python performance_testing/run_load_tests.py --single-level 100

# Run custom load levels
python performance_testing/run_load_tests.py --levels 50 100 150
```

#### Run Individual Tests

```bash
# Run specific user count tests
python performance_testing/individual_tests.py 100
python performance_testing/individual_tests.py 500 --url http://localhost:8000
```

### 4. Run with PyTest

```bash
# Run all performance tests
pytest performance_testing/ -m performance

# Run specific load test
pytest performance_testing/test_performance.py::TestLoadPerformance::test_load_test_100_users

# Run with custom markers
pytest performance_testing/ -m "performance and not slow"
```

## Usage Examples

### Basic Load Test

```python
import asyncio
from performance_testing.load_test_framework import LoadTestRunner

async def run_basic_test():
    runner = LoadTestRunner("http://localhost:8000")
    result = await runner.run_load_test(num_users=100)

    print(f"Success Rate: {(result.successful_users/result.total_users)*100:.1f}%")
    print(f"Throughput: {result.throughput_per_second:.2f} users/sec")

asyncio.run(run_basic_test())
```

### Custom Configuration

```python
from performance_testing.config import PerformanceTestConfig
from performance_testing.load_test_framework import LoadTestRunner

# Create custom config
config = PerformanceTestConfig(
    base_url="http://localhost:8000",
    max_concurrent_requests=30,
    timeout=120.0,
    db_url="postgresql://user:pass@localhost/db"
)

# Run test with config
runner = LoadTestRunner(config.base_url, config.db_url)
result = await runner.run_load_test(100, config.max_concurrent_requests)
```

### Automated Test Suite

```python
from performance_testing.run_load_tests import AutomatedLoadTestSuite

async def run_full_suite():
    suite = AutomatedLoadTestSuite(
        base_url="http://localhost:8000",
        db_url="postgresql://user:pass@localhost/db"
    )

    # Run all load levels
    results = await suite.run_all_load_levels([100, 200, 400])

    # Generate reports
    summary_file = suite.generate_comprehensive_report()
    print(f"Report generated: {summary_file}")

asyncio.run(run_full_suite())
```

## Test Process Flow

Each user goes through the complete registration and verification process:

1. **Frontend Simulation**

   - Generate wallet (simulated timing)
   - Encrypt wallet (simulated timing)
   - Gather network info (simulated timing)

2. **Registration Phase**

   - Call `/auth/v1/register` endpoint
   - Measure `smt_local_add_time`
   - Store registration metrics

3. **Polling Phase**

   - Poll `/auth/v1/poll/{did_str}` until approved
   - Capture `vc_issuance_time` and `smt_onchain_add_time`

4. **Verification Phase**

   - Generate VP (simulated timing)
   - Call `/auth/v1/verify` endpoint
   - Measure all verification timings

5. **Metrics Storage**
   - Store all metrics in `times_of_time` table
   - Generate comprehensive reports

## Configuration Options

### Environment Variables

- `PERF_TEST_BASE_URL` - Base URL for API calls (default: http://localhost:8000)
- `PERF_TEST_DB_URL` - PostgreSQL connection string
- `PERF_TEST_TIMEOUT` - Request timeout in seconds (default: 60)
- `PERF_TEST_MAX_CONCURRENT` - Max concurrent requests (default: 50)
- `PERF_TEST_OUTPUT_DIR` - Output directory for reports (default: performance_reports)

### Command Line Options

```bash
# run_load_tests.py options
--url TEXT              Base URL for the connector API
--db-url TEXT           PostgreSQL database URL
--levels INT [INT ...]  Load levels to test
--output-dir TEXT       Output directory for reports
--single-level INT      Run only a single load level

# PyTest options
--skip-performance      Skip performance tests
--performance-only      Run only performance tests
--load-level INT        Run with specific user count
```

## Output and Reports

The framework generates several types of output:

### 1. Real-time Console Output

- Test progress and status
- Success/failure counts
- Immediate performance metrics

### 2. Markdown Reports

- Individual reports per load level
- Comprehensive summary report
- Detailed timing breakdowns
- Error analysis and recommendations

### 3. JSON Data Files

- Raw test data for further analysis
- User-level metrics
- Aggregated statistics

### 4. Database Storage

- Individual user metrics in `times_of_time` table
- Queryable for custom analysis

## Report Structure

### Summary Report Example

```markdown
# Load Test Summary Report

## Overview

- Load Levels Tested: [100, 200, 400, 800, 1000]
- Total Tests: 5

## Summary Results

| Users | Success Rate | Throughput (u/s) | Avg Total Time (s) | 95th Percentile (s) |
| ----- | ------------ | ---------------- | ------------------ | ------------------- |
| 100   | 95.0%        | 3.45             | 28.5               | 45.2                |
| 200   | 92.5%        | 6.12             | 32.1               | 52.8                |

## Performance Analysis

- Peak Throughput: 6.12 users/second at 200 users
- Success Rate Range: 89.2% - 95.0%
- Response Time Range: 28.5s - 65.3s

## Recommendations

- Optimal load level appears to be around 200 users
- Consider optimization for loads above 800 users
```

## Performance Criteria

The framework includes configurable performance assertions:

- **Success Rate**: Should be > 90% for loads up to 400 users
- **Response Time**: Should be < 60s average for 100 users
- **Error Rate**: Should be < 10% under normal load
- **Throughput**: Should scale reasonably with user count

## Troubleshooting

### Common Issues

1. **Connection Errors**

   - Ensure the Blackgate Connector is running
   - Check the base URL configuration
   - Verify network connectivity

2. **Database Connection Issues**

   - Verify PostgreSQL connection string
   - Ensure database user has proper permissions
   - Check that `times_of_time` table exists

3. **High Error Rates**

   - Reduce concurrent request count
   - Check server resource usage
   - Verify test data validity

4. **Slow Performance**
   - Monitor server resources
   - Adjust timeout values
   - Check database performance

### Debug Mode

Enable debug logging:

```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

### Validation

Run configuration validation:

```python
from performance_testing.config import PerformanceTestConfig, PerformanceTestValidator

config = PerformanceTestConfig.from_env()
validator = PerformanceTestValidator(config)

if validator.validate_all():
    print("✅ Configuration valid")
else:
    print(validator.get_validation_report())
```

## Integration

### CI/CD Integration

```yaml
# Example GitHub Actions workflow
- name: Run Performance Tests
  run: |
    python performance_testing/run_load_tests.py \
      --url ${{ env.API_URL }} \
      --levels 100 200 \
      --output-dir ./performance_reports

- name: Upload Performance Reports
  uses: actions/upload-artifact@v3
  with:
    name: performance-reports
    path: ./performance_reports/
```

### Custom Metrics

Extend the framework with custom metrics:

```python
from performance_testing.load_test_framework import UserMetrics

class CustomUserMetrics(UserMetrics):
    custom_metric: float = 0.0

    def calculate_custom_metric(self):
        # Custom calculation logic
        self.custom_metric = self.total_process_time * 2
```

## Best Practices

1. **Start Small**: Begin with lower load levels to establish baseline
2. **Monitor Resources**: Watch server CPU, memory, and database performance
3. **Consistent Environment**: Use dedicated test environment
4. **Regular Testing**: Run performance tests regularly to catch regressions
5. **Analyze Trends**: Compare results over time to identify performance trends

## Support

For issues or questions:

1. Check the troubleshooting section
2. Review the configuration validation
3. Enable debug logging for detailed information
4. Check server logs for backend issues
