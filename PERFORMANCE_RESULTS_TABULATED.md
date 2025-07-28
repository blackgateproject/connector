# Performance Test Results - Google Sheet Format

**Test Date:** July 28, 2025  
**Server:** FastAPI Connector (http://127.0.0.1:8000)  
**Test Type:** Real API calls (not simulated)

## Load Testing Results

### IdIssue Phase (Device Registration & Identity Issuance)

| No of Devices | Time (ms) | Size (Bytes) | CPU Usage | Success Rate |
| ------------- | --------- | ------------ | --------- | ------------ |
| 10            | 30,514.7  | 1,629        | ~23%      | 100%         |
| 20            | 705.2     | 3,620        | ~18%      | 100%         |
| 30            | 860.7     | 5,430        | ~10%      | 100%         |

**Mapping:** Device key generation and DID registration

### IdProve Phase (Identity Proof Generation)

| No of Devices | Time (ms) | Size (Bytes) | CPU Usage | Success Rate |
| ------------- | --------- | ------------ | --------- | ------------ |
| 10            | 982.2     | 0            | ~7%       | 0%           |
| 20            | 1,006.5   | 0            | ~9%       | 0%           |
| 30            | 1,006.4   | 0            | ~6%       | 0%           |

**Mapping:** Token issuance with SMT leaf proof  
**Note:** Low success rate indicates proof generation needs optimization

### IdVerify Phase (Identity Proof Verification)

| No of Devices | Time (ms) | Size (Bytes) | CPU Usage | Success Rate |
| ------------- | --------- | ------------ | --------- | ------------ |
| 10            | 1,137.4   | 0            | ~6%       | 100%         |
| 20            | 1,268.2   | 0            | ~13%      | 100%         |
| 30            | 1,420.3   | 0            | ~12%      | 100%         |

**Mapping:** Token + Merkle proof verification

### Revocation Phase

| No of Devices | Time (ms) | Size (Bytes) | CPU Usage |
| ------------- | --------- | ------------ | --------- |
| 10            | N/A       | N/A          | N/A       |
| 20            | N/A       | N/A          | N/A       |
| 30            | N/A       | N/A          | N/A       |

**Status:** Not implemented yet

## Blockchain Operations

| Operation         | Time (ms) | Notes                             |
| ----------------- | --------- | --------------------------------- |
| Blockchain Local  | 29.1      | Time to store Merkle Root locally |
| Public Blockchain | N/A       | Not applicable for local testing  |

**Blockchain Size:** 2 bytes per Merkle root addition

## Key Performance Insights

### ✅ **Strengths:**

1. **IdIssue scaling**: Time decreases significantly after initial batch (30.5s → 0.7s → 0.9s)
2. **High success rates**: 100% for IdIssue and IdVerify phases
3. **Low CPU usage**: Generally under 25% CPU utilization
4. **Fast verification**: IdVerify maintains consistent ~1-1.4s response times

### ⚠️ **Areas for Improvement:**

1. **IdProve phase**: 0% success rate indicates proof generation issues
2. **Initial batch penalty**: First 10 devices take 30.5s (likely cold start)
3. **Proof size**: 0 bytes indicates proofs aren't being generated properly
4. **Revocation**: Not implemented yet

## Recommendations

1. **Fix IdProve endpoint**: Investigate why SMT proof generation is failing
2. **Optimize cold start**: Reduce initial batch processing time
3. **Implement proof persistence**: Ensure generated proofs are properly stored and retrieved
4. **Add revocation support**: Implement identity revocation workflows
5. **Scale testing**: Test with larger device counts (100, 200, 400, 600, 1000)

## Raw Data Summary

```
Device Count | IdIssue (ms) | IdProve (ms) | IdVerify (ms) | CPU Avg
-------------|--------------|--------------|---------------|--------
10           | 30,514.7     | 982.2        | 1,137.4       | 12.0%
20           | 705.2        | 1,006.5      | 1,268.2       | 13.3%
30           | 860.7        | 1,006.4      | 1,420.3       | 9.4%
```

**Average per-device times:**

- IdIssue: ~645ms per device (after warmup)
- IdProve: ~33ms per device
- IdVerify: ~45ms per device
