import binascii
import subprocess
import loaders
import os
import pathlib
import pytest

# Exit codes for the hash test program
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

def run_hash_program(hash_func, input_data, monte=False):
    """
    Run the 'hash' test program that calculates and prints the hash of
    data provided to its standard input.

    The test is skipped if the specified hash_func is disabled in the
    Tux configuration.
    """

    prog = _this_file_dir / "programs" / "hash" / "bin" / "hash"

    if monte:
        args = [prog, hash_func, "--monte"]
    else:
        args = [prog, hash_func]

    completed_process = subprocess.run(
        args=args,
        input=input_data,
        stdout=subprocess.PIPE
    )

    if completed_process.returncode == DISABLED_ALGO_EXIT_CODE:
        pytest.skip(f"Skipping tests for disabled algorithm: {hash_func}")

    return completed_process.stdout.decode().strip().lower()

def run_msg_test_vector(hash_func, test_vector):
    """Run a test vector from a "Msg" response file """
    len_bits = int(test_vector["Len"])
    msg = binascii.unhexlify(test_vector["Msg"])

    assert len_bits % 8 == 0

    len_bytes = len_bits // 8

    calculated_md = run_hash_program(hash_func, msg[0:len_bytes])

    assert test_vector["MD"].lower() == calculated_md

def run_monte_test_vector(hash_func, seed, count, expected_md):
    """Run a test vector from a "Monte Carlo" response file """
    seed = binascii.unhexlify(seed)
    expected_md = expected_md

    md = run_hash_program(hash_func, seed, monte=True)

    assert md == expected_md.lower(), f"Wrong hash at checkpoint {count}"

##############
# NIST Tests #
##############

test_vectors_dir = _this_file_dir / "test_vectors" / "NIST" / "shabytetestvectors"

# ShortMsg test vectors

@loaders.load_msg_rsp_test_vectors(test_vectors_dir / "SHA224ShortMsg.rsp")
def test_sha224_short_msg(test_vector):
    run_msg_test_vector("SHA224", test_vector)

@loaders.load_msg_rsp_test_vectors(test_vectors_dir / "SHA256ShortMsg.rsp")
def test_sha256_short_msg(test_vector):
    run_msg_test_vector("SHA256", test_vector)

@loaders.load_msg_rsp_test_vectors(test_vectors_dir / "SHA384ShortMsg.rsp")
def test_sha384_short_msg(test_vector):
    run_msg_test_vector("SHA384", test_vector)

@loaders.load_msg_rsp_test_vectors(test_vectors_dir / "SHA512ShortMsg.rsp")
def test_sha512_short_msg(test_vector):
    run_msg_test_vector("SHA512", test_vector)

@loaders.load_msg_rsp_test_vectors(test_vectors_dir / "SHA512_224ShortMsg.rsp")
def test_sha512_224_short_msg(test_vector):
    run_msg_test_vector("SHA512_224", test_vector)

@loaders.load_msg_rsp_test_vectors(test_vectors_dir / "SHA512_256ShortMsg.rsp")
def test_sha512_256_short_msg(test_vector):
    run_msg_test_vector("SHA512_256", test_vector)

# LongMsg test vectors

@loaders.load_msg_rsp_test_vectors(test_vectors_dir / "SHA224LongMsg.rsp")
def test_sha224_long_msg(test_vector):
    run_msg_test_vector("SHA224", test_vector)

@loaders.load_msg_rsp_test_vectors(test_vectors_dir / "SHA256LongMsg.rsp")
def test_sha256_long_msg(test_vector):
    run_msg_test_vector("SHA256", test_vector)

@loaders.load_msg_rsp_test_vectors(test_vectors_dir / "SHA384LongMsg.rsp")
def test_sha384_long_msg(test_vector):
    run_msg_test_vector("SHA384", test_vector)

@loaders.load_msg_rsp_test_vectors(test_vectors_dir / "SHA512LongMsg.rsp")
def test_sha512_long_msg(test_vector):
    run_msg_test_vector("SHA512", test_vector)

@loaders.load_msg_rsp_test_vectors(test_vectors_dir / "SHA512_224LongMsg.rsp")
def test_sha512_224_long_msg(test_vector):
    run_msg_test_vector("SHA512_224", test_vector)

@loaders.load_msg_rsp_test_vectors(test_vectors_dir / "SHA512_256LongMsg.rsp")
def test_sha512_256_long_msg(test_vector):
    run_msg_test_vector("SHA512_256", test_vector)

# Monte RSP test vectors

@loaders.load_monte_rsp_test_vectors("Seed,COUNT,MD", test_vectors_dir / "SHA224Monte.rsp")
def test_sha224_monte_rsp(Seed, COUNT, MD):
    run_monte_test_vector("SHA224", Seed, COUNT, MD)

@loaders.load_monte_rsp_test_vectors("Seed,COUNT,MD", test_vectors_dir / "SHA256Monte.rsp")
def test_sha256_monte_rsp(Seed, COUNT, MD):
    run_monte_test_vector("SHA256", Seed, COUNT, MD)

@loaders.load_monte_rsp_test_vectors("Seed,COUNT,MD", test_vectors_dir / "SHA384Monte.rsp")
def test_sha384_monte_rsp(Seed, COUNT, MD):
    run_monte_test_vector("SHA384", Seed, COUNT, MD)

@loaders.load_monte_rsp_test_vectors("Seed,COUNT,MD", test_vectors_dir / "SHA512Monte.rsp")
def test_sha512_monte_rsp(Seed, COUNT, MD):
    run_monte_test_vector("SHA512", Seed, COUNT, MD)

@loaders.load_monte_rsp_test_vectors("Seed,COUNT,MD", test_vectors_dir / "SHA512_224Monte.rsp")
def test_sha512_224_monte_rsp(Seed, COUNT, MD):
    run_monte_test_vector("SHA512_224", Seed, COUNT, MD)

@loaders.load_monte_rsp_test_vectors("Seed,COUNT,MD", test_vectors_dir / "SHA512_256Monte.rsp")
def test_sha512_256_monte_rsp(Seed, COUNT, MD):
    run_monte_test_vector("SHA512_256", Seed, COUNT, MD)