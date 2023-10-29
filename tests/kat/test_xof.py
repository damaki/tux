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


def run_xof_program(
    xof_func, input_data, output_len_bytes, monte=False, minoutlen=0, maxoutlen=0
):
    """
    Run the 'xof' test program that calculates and prints the xof of
    data provided to its standard input.

    The test is skipped if the specified xof_func is disabled in the
    Tux configuration.
    """

    prog = _this_file_dir / "programs" / "xof" / "bin" / "xof"

    completed_process = subprocess.run(
        args=[prog, xof_func, str(output_len_bytes)],
        input=input_data,
        stdout=subprocess.PIPE,
    )

    if completed_process.returncode == DISABLED_ALGO_EXIT_CODE:
        pytest.skip(f"Skipping tests for disabled algorithm: {xof_func}")

    return completed_process.stdout.decode().strip().lower()


def run_xof_monte_program(
    xof_func, seed, minoutbytes, maxoutbytes
):
    """
    Run the 'xof_monte' test program that runs the monte carlo test

    The test is skipped if the specified xof_func is disabled in the
    Tux configuration.
    """

    prog = _this_file_dir / "programs" / "xof_monte" / "bin" / "xof_monte"

    completed_process = subprocess.run(
        args=[prog, xof_func, str(minoutbytes), str(maxoutbytes), seed],
        stdout=subprocess.PIPE,
    )

    if completed_process.returncode == DISABLED_ALGO_EXIT_CODE:
        pytest.skip(f"Skipping tests for disabled algorithm: {xof_func}")

    return completed_process.stdout.decode().strip().lower()


def run_msg_test_vector(xof_func, test_vector):
    """Run a test vector from a "Msg" response file"""
    len_bits = int(test_vector["Len"])
    msg = binascii.unhexlify(test_vector["Msg"])
    output = binascii.unhexlify(test_vector["Output"])

    assert len_bits % 8 == 0

    len_bytes = len_bits // 8

    calculated_output = run_xof_program(xof_func, msg[0:len_bytes], len(output))

    assert test_vector["Output"].lower() == calculated_output


def run_monte_test_vector(hash_func, filename):
    """Run a test vector from a "Monte Carlo" response file"""
    test_attributes, test_vectors = loaders.load_shake_monte_rsp_test_vectors(filename)

    minoutlen = test_attributes["Minimum Output Length (bits)"]
    maxoutlen = test_attributes["Maximum Output Length (bits)"]

    seed = test_vectors[0]["Msg"]

    output = run_xof_monte_program(
        hash_func,
        seed,
        minoutbytes=int(minoutlen) // 8,  # convert bits to bytes
        maxoutbytes=int(maxoutlen) // 8,  # convert bits to bytes
    )

    digests = output.splitlines()

    assert len(digests) == 100, "Expected 100 checkpoint digests"

    for test_vector in test_vectors[1:]:
        count = int(test_vector["COUNT"])
        assert digests[count] == test_vector["Output"], f"Wrong digest at checkpoint {count}"


##############
# NIST Tests #
##############

shakebytetestvectors = _this_file_dir / "test_vectors" / "NIST" / "shakebytetestvectors"

# ShortMsg test vectors


@loaders.load_msg_rsp_test_vectors(shakebytetestvectors / "SHAKE128ShortMsg.rsp")
def test_shake128_short_msg(test_vector):
    run_msg_test_vector("SHAKE128", test_vector)


@loaders.load_msg_rsp_test_vectors(shakebytetestvectors / "SHAKE256ShortMsg.rsp")
def test_shake256_short_msg(test_vector):
    run_msg_test_vector("SHAKE256", test_vector)


# LongMsg test vectors


@loaders.load_msg_rsp_test_vectors(shakebytetestvectors / "SHAKE128LongMsg.rsp")
def test_shake128_long_msg(test_vector):
    run_msg_test_vector("SHAKE128", test_vector)


@loaders.load_msg_rsp_test_vectors(shakebytetestvectors / "SHAKE256LongMsg.rsp")
def test_shake256_long_msg(test_vector):
    run_msg_test_vector("SHAKE256", test_vector)


# Monte Carlo test vectors


def test_shake128_monte_rsp():
    run_monte_test_vector("SHAKE128", shakebytetestvectors / "SHAKE128Monte.rsp")


def test_shake256_monte_rsp():
    run_monte_test_vector("SHAKE256", shakebytetestvectors / "SHAKE256Monte.rsp")
