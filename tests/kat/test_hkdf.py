import subprocess
import loaders
import os
import pathlib
import pytest

# Exit codes for the hkdf test program
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

# These functions handle the running of different kinds of test vectors

def run_hkdf_program(hash_func: str, ikm: str, salt: str, info: str, okm_len: int):
    """
    Run the 'hkdf' test program that calculates and prints the output key material (OKM)
    calculated from the provided IKM, salt, and info.
    """

    print(f"hash_func: '{hash_func}'")
    print(f"ikm: '{ikm}'")
    print(f"salt: '{salt}'")
    print(f"info: '{info}'")
    print(f"okm_len: {okm_len}")

    prog = _this_file_dir / "programs" / "hkdf" / "bin" / "hkdf"

    completed_process = subprocess.run(
        args=[prog, hash_func, ikm, info, okm_len, salt],
        stdout=subprocess.PIPE
    )

    if completed_process.returncode == DISABLED_ALGO_EXIT_CODE:
        pytest.skip(f"Skipping tests for disabled algorithm: {hash_func}")

    return completed_process.stdout.decode().strip().lower()

##############
# NIST tests #
##############

nist_test_vectors_dir = _this_file_dir / "test_vectors" / "NIST" / "hkdftestvectors"

@loaders.load_msg_rsp_test_vectors(nist_test_vectors_dir / "HKDF.rsp")
def test_hkdf_nist(test_vector):

    # Not all hash lengths in HKDF.rsp are supported.

    hash_func = test_vector["Hash"].replace("-", "")
    if hash_func not in ["SHA1", "SHA256"]:
        pytest.skip(f"Skipping test for unsupported hash function: {hash_func}")

    calculated_okm = run_hkdf_program(
        hash_func,
        test_vector["IKM"],
        test_vector["salt"],
        test_vector["info"],
        test_vector["L"]
    )

    assert test_vector["OKM"].lower() == calculated_okm

############################
# Project Wycheproof Tests #
############################

def run_wycheproof_hkdf_test(algorithm: str, test_vector: dict):
    """
    Read test vector data from a Project Wycheproof test vector, run the
    HKDF test driver, and compare the results.
    """
    calculated_okm = run_hkdf_program(
        algorithm,
        test_vector["ikm"],
        test_vector["salt"],
        test_vector["info"],
        str(test_vector["size"])
    )

    assert test_vector["okm"].lower() == calculated_okm

wp_test_vectors_dir = _this_file_dir / "test_vectors" / "wycheproof"

@loaders.load_wycheproof_test_vectors(wp_test_vectors_dir / "hkdf_sha1_test.json")
def test_hkdf_wycheproof_sha1(test_vector):
    run_wycheproof_hkdf_test("SHA1", test_vector)

@loaders.load_wycheproof_test_vectors(wp_test_vectors_dir / "hkdf_sha256_test.json")
def test_hkdf_wycheproof_sha256(test_vector):
    run_wycheproof_hkdf_test("SHA256", test_vector)

@loaders.load_wycheproof_test_vectors(wp_test_vectors_dir / "hkdf_sha384_test.json")
def test_hkdf_wycheproof_sha384(test_vector):
    run_wycheproof_hkdf_test("SHA384", test_vector)

@loaders.load_wycheproof_test_vectors(wp_test_vectors_dir / "hkdf_sha512_test.json")
def test_hkdf_wycheproof_sha512(test_vector):
    run_wycheproof_hkdf_test("SHA512", test_vector)