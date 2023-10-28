import binascii
import subprocess
import loaders
import os
import pathlib
import pytest

# Exit codes for the hmac test program
SUCCESS_EXIT_CODE = 0
ERROR_EXIT_CODE = 1
DISABLED_ALGO_EXIT_CODE = 2

def pytest_generate_tests(metafunc):
    if getattr(metafunc.function, "tc_cases", None):
        metafunc.parametrize(metafunc.function.tc_params, metafunc.function.tc_cases)

_this_file_dir = pathlib.Path(os.path.realpath(os.path.dirname(__file__)))

#######################
# Test Vector Runners #
#######################

# These functions run specific kinds of test vectors.

def run_hmac_program(hash_func: str, key: str, input_data: bytes, mac: str):
    """
    Run the 'hash' test program that calculates and prints the hash of
    data provided to its standard input.
    """
    prog = _this_file_dir / "programs" / "hmac" / "bin" / "hmac"

    completed_process = subprocess.run(
        args=[prog, hash_func, key, mac],
        input=input_data,
        stdout=subprocess.PIPE
    )

    if completed_process.returncode == DISABLED_ALGO_EXIT_CODE:
        pytest.skip(f"Skipping tests for disabled algorithm: {hash_func}")
    print(completed_process.stdout.decode())
    return completed_process.stdout.decode().strip().lower().split(",")

##############
# NIST Tests #
##############

nist_test_vectors_dir = _this_file_dir / "test_vectors" / "NIST" / "hmactestvectors"

@loaders.load_msg_rsp_test_vectors(nist_test_vectors_dir / "HMAC.rsp")
def test_hmac_nist(test_vector):

    # Not all hash lengths in HMAC.rsp are supported.

    hash_funcs = {
        20: "SHA1",
        28: "SHA224",
        32: "SHA256",
        48: "SHA384",
        64: "SHA512"
    }

    L = int(test_vector["L"])

    if L not in hash_funcs.keys():
        pytest.skip(f"Skipping test for unsupported hash function with L = {L}")

    calculated_mac, verify_result = run_hmac_program(
        hash_funcs[L],
        test_vector["Key"],
        binascii.unhexlify(test_vector["Msg"]),
        test_vector["Mac"]
    )

    expected_mac = test_vector["Mac"]

    assert expected_mac.lower() == calculated_mac[0:len(expected_mac)]
    assert verify_result == "valid"

############################
# Project Wycheproof Tests #
############################

def run_wycheproof_test(algorithm, test_vector):
    """Run a HMAC test using a Project Wycheproof test vector"""
    calculated_mac, verify_result = run_hmac_program(
        algorithm,
        test_vector["key"],
        binascii.unhexlify(test_vector["msg"]),
        test_vector["tag"]
    )

    expected_mac = test_vector["tag"]

    assert test_vector["result"] == verify_result

    if test_vector["result"] == "invalid":
        assert expected_mac.lower() != calculated_mac[0:len(expected_mac)]
    else:
        assert expected_mac.lower() == calculated_mac[0:len(expected_mac)]

wp_test_vectors_dir = _this_file_dir / "test_vectors" / "wycheproof"

@loaders.load_wycheproof_test_vectors(wp_test_vectors_dir / "hmac_sha1_test.json")
def test_hmac_wycheproof_sha1(test_vector):
    run_wycheproof_test("SHA1", test_vector)

@loaders.load_wycheproof_test_vectors(wp_test_vectors_dir / "hmac_sha224_test.json")
def test_hmac_wycheproof_sha224(test_vector):
    run_wycheproof_test("SHA224", test_vector)

@loaders.load_wycheproof_test_vectors(wp_test_vectors_dir / "hmac_sha256_test.json")
def test_hmac_wycheproof_sha256(test_vector):
    run_wycheproof_test("SHA256", test_vector)

@loaders.load_wycheproof_test_vectors(wp_test_vectors_dir / "hmac_sha384_test.json")
def test_hmac_wycheproof_sha384(test_vector):
    run_wycheproof_test("SHA384", test_vector)

@loaders.load_wycheproof_test_vectors(wp_test_vectors_dir / "hmac_sha512_test.json")
def test_hmac_wycheproof_sha512(test_vector):
    run_wycheproof_test("SHA512", test_vector)

@loaders.load_wycheproof_test_vectors(wp_test_vectors_dir / "hmac_sha3_224_test.json")
def test_hmac_wycheproof_sha3_224(test_vector):
    run_wycheproof_test("SHA3_224", test_vector)

@loaders.load_wycheproof_test_vectors(wp_test_vectors_dir / "hmac_sha3_256_test.json")
def test_hmac_wycheproof_sha3_256(test_vector):
    run_wycheproof_test("SHA3_256", test_vector)

@loaders.load_wycheproof_test_vectors(wp_test_vectors_dir / "hmac_sha3_384_test.json")
def test_hmac_wycheproof_sha3_384(test_vector):
    run_wycheproof_test("SHA3_384", test_vector)

@loaders.load_wycheproof_test_vectors(wp_test_vectors_dir / "hmac_sha3_512_test.json")
def test_hmac_wycheproof_sha3_512(test_vector):
    run_wycheproof_test("SHA3_512", test_vector)