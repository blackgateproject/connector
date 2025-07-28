"""
Simple performance test for SMT operations.
Tests current performance without complex imports.
"""

import os
import statistics
import sys
import time

# Add app to path
sys.path.append(os.path.join(os.path.dirname(__file__), "app"))


def test_smt_performance():
    """Test SMT operations performance."""
    print("🚀 Simple SMT Performance Test")
    print("=" * 50)

    try:
        # Import SMT core
        from app.core.sparseMerkleTree import smtCore
        from app.utils.performance_optimizations import optimized_smt

        print("✅ Successfully imported SMT components")

        # Test data
        test_users = [f"did:ethr:blackgate:test_user_{i}" for i in range(10)]
        test_credentials = [f"test_credentials_{i}" for i in range(10)]

        print(f"📊 Testing with {len(test_users)} users")

        # Test 1: User Addition Performance
        print("\n1️⃣ User Addition Performance:")
        add_times = []

        for i, (user_id, creds) in enumerate(zip(test_users, test_credentials)):
            start_time = time.time()
            try:
                result = smtCore.add_user(user_id, creds)
                add_time = (time.time() - start_time) * 1000  # Convert to ms
                add_times.append(add_time)
                print(f"   User {i+1}: {add_time:.2f}ms")
            except Exception as e:
                print(f"   User {i+1}: ERROR - {e}")

        if add_times:
            print(f"   📈 Average add time: {statistics.mean(add_times):.2f}ms")
            print(f"   📈 Min/Max: {min(add_times):.2f}ms / {max(add_times):.2f}ms")

        # Test 2: Proof Generation Performance (IdProve equivalent)
        print("\n2️⃣ Proof Generation Performance (IdProve):")
        proof_times = []

        for i, user_id in enumerate(test_users):
            start_time = time.time()
            try:
                proof = smtCore.get_proof(user_id)
                proof_time = (time.time() - start_time) * 1000  # Convert to ms
                proof_times.append(proof_time)
                print(f"   User {i+1}: {proof_time:.2f}ms")
            except Exception as e:
                print(f"   User {i+1}: ERROR - {e}")

        if proof_times:
            avg_proof_time = statistics.mean(proof_times)
            print(f"   📈 Average proof generation: {avg_proof_time:.2f}ms")
            print(f"   📈 Min/Max: {min(proof_times):.2f}ms / {max(proof_times):.2f}ms")

            # Check against target
            target_prove_time = 12.0  # Target: <12ms
            if avg_proof_time <= target_prove_time:
                print(
                    f"   ✅ MEETS TARGET: {avg_proof_time:.2f}ms ≤ {target_prove_time}ms"
                )
            else:
                print(
                    f"   ❌ ABOVE TARGET: {avg_proof_time:.2f}ms > {target_prove_time}ms"
                )

        # Test 3: Proof Verification Performance (IdVerify equivalent)
        print("\n3️⃣ Proof Verification Performance (IdVerify):")
        verify_times = []

        for i, (user_id, creds) in enumerate(zip(test_users, test_credentials)):
            try:
                # Get proof first
                proof = smtCore.get_proof(user_id)
                root_hash = smtCore.smt.root

                # Measure verification time
                start_time = time.time()
                is_valid, verify_time = optimized_smt.optimized_proof_verification(
                    creds, proof, root_hash
                )
                actual_verify_time = (time.time() - start_time) * 1000  # Convert to ms
                verify_times.append(actual_verify_time)

                status = "✅" if is_valid else "❌"
                print(f"   User {i+1}: {actual_verify_time:.2f}ms {status}")

            except Exception as e:
                print(f"   User {i+1}: ERROR - {e}")

        if verify_times:
            avg_verify_time = statistics.mean(verify_times)
            print(f"   📈 Average verification: {avg_verify_time:.2f}ms")
            print(
                f"   📈 Min/Max: {min(verify_times):.2f}ms / {max(verify_times):.2f}ms"
            )

            # Check against target
            target_verify_time = 4.0  # Target: <4ms
            if avg_verify_time <= target_verify_time:
                print(
                    f"   ✅ MEETS TARGET: {avg_verify_time:.2f}ms ≤ {target_verify_time}ms"
                )
            else:
                print(
                    f"   ❌ ABOVE TARGET: {avg_verify_time:.2f}ms > {target_verify_time}ms"
                )

        # Summary
        print("\n📋 Performance Summary:")
        print("=" * 50)
        if add_times:
            print(f"📊 User Addition: {statistics.mean(add_times):.2f}ms avg")
        if proof_times:
            print(
                f"🔍 Proof Generation (IdProve): {statistics.mean(proof_times):.2f}ms avg (target: <12ms)"
            )
        if verify_times:
            print(
                f"✅ Proof Verification (IdVerify): {statistics.mean(verify_times):.2f}ms avg (target: <4ms)"
            )

        # Performance assessment
        if proof_times and verify_times:
            prove_meets_target = statistics.mean(proof_times) <= 12.0
            verify_meets_target = statistics.mean(verify_times) <= 4.0

            if prove_meets_target and verify_meets_target:
                print("\n🎉 ALL PERFORMANCE TARGETS MET!")
            else:
                print("\n⚠️  Performance improvements needed:")
                if not prove_meets_target:
                    print(
                        f"   - IdProve: {statistics.mean(proof_times):.2f}ms > 12ms target"
                    )
                if not verify_meets_target:
                    print(
                        f"   - IdVerify: {statistics.mean(verify_times):.2f}ms > 4ms target"
                    )

    except Exception as e:
        print(f"❌ Test failed: {e}")
        import traceback

        traceback.print_exc()


if __name__ == "__main__":
    test_smt_performance()
