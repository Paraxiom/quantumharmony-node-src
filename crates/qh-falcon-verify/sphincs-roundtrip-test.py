"""Test qh-falcon-verify end-to-end: SPHINCS+-SHAKE-256s sign + verify cycle."""
import subprocess, sys
import pqcrypto.sign.sphincs_shake_256s_simple as sphincs

pk, sk = sphincs.generate_keypair()
print(f"pubkey: {len(pk)} bytes, secret: {len(sk)} bytes")

msg = b'{"image_tag":"sylvaincormier/quantumharmony-node:v45","spec_version":38}'
sig = sphincs.sign(sk, msg)  # already detached
print(f"detached sig: {len(sig)} bytes")

# Round-trip in Python
sphincs.verify(pk, msg, sig)
print("Python round-trip: OK")

with open("/tmp/qh-test-msg.txt", "wb") as f: f.write(msg)

# Test 1: valid signature → exit 0
r = subprocess.run(
    ["./target/release/qh-falcon-verify", pk.hex(), "/tmp/qh-test-msg.txt", sig.hex()],
    capture_output=True, text=True
)
print(f"[Test 1] valid sig -> exit {r.returncode} {('PASS' if r.returncode==0 else 'FAIL: '+r.stderr.strip())}")
if r.returncode != 0: sys.exit(1)

# Test 2: tampered message → exit 1
with open("/tmp/qh-test-msg.txt", "wb") as f: f.write(msg + b"X")
r = subprocess.run(["./target/release/qh-falcon-verify", pk.hex(), "/tmp/qh-test-msg.txt", sig.hex()], capture_output=True, text=True)
print(f"[Test 2] tampered msg -> exit {r.returncode} {('PASS' if r.returncode==1 else 'FAIL')}")

# Test 3: tampered signature → exit 1
with open("/tmp/qh-test-msg.txt", "wb") as f: f.write(msg)
bad = bytearray(sig); bad[100] ^= 0xFF
r = subprocess.run(["./target/release/qh-falcon-verify", pk.hex(), "/tmp/qh-test-msg.txt", bytes(bad).hex()], capture_output=True, text=True)
print(f"[Test 3] tampered sig -> exit {r.returncode} {('PASS' if r.returncode==1 else 'FAIL')}")

# Test 4: wrong pubkey → exit 1
wrong_pk, _ = sphincs.generate_keypair()
r = subprocess.run(["./target/release/qh-falcon-verify", wrong_pk.hex(), "/tmp/qh-test-msg.txt", sig.hex()], capture_output=True, text=True)
print(f"[Test 4] wrong pk -> exit {r.returncode} {('PASS' if r.returncode==1 else 'FAIL')}")

print("\n=== ALL TESTS PASSED ✓ ===")
