import re
import json
from pathlib import Path

def load_msg_rsp_test_vectors(filename):
    """
    PyTest decorator to load test vectors from "Msg" response files
    (e.g. SHA224ShortMsg.rsp) to parameterize the test.

        Parameters:
            tc_params: A string containing a comma-separated list of
                       keys to pick from each test vector from the file.
                       For example: "Len, Msg, MD"
            filename: The name of the test vector response file to load.
    """

    def wrapper(function):
        test_vectors = []
        test_vector = {
            "file": Path(filename).name
        }
        common_params = {}

        with open(filename, 'r') as f:

            line_num = 1

            for line in f.readlines():
                # Consecutive lines in the format "Key = Value" are considered
                # as a single test vector. Blank lines or lines containing
                # anything else are considered as separators between test vectors

                if m := re.match(r"^(\w+)\s*=\s*(.*)$", line):
                    test_vector[m.group(1)] = m.group(2)

                    if "line" not in test_vector:
                        test_vector["line"] = line_num

                elif m:= re.match(r"^\[(\w+)\s*=\s*(.+)\]$", line):
                    common_params = {m.group(1): m.group(2)}

                elif len(test_vector) > 1:
                    test_vectors.append({**common_params, **test_vector})
                    test_vector = {
                        "file": Path(filename).name
                    }

                line_num += 1

        function.tc_cases = test_vectors
        function.tc_params = "test_vector"

        return function
    return wrapper

def load_monte_rsp_test_vectors(tc_params, filename):
    """
    PyTest decorator to load test vectors from "Monte Carlo" response files
    (e.g. SHA224Monte.rsp) to parameterize the test.

        Parameters:
            tc_params: A string containing a comma-separated list of
                       keys to pick from each test vector from the file.
                       For example: "Seed, COUNT, MD"
            filename: The name of the test vector response file to load.
    """
    params = [x.strip() for x in tc_params.split(',')]

    def wrapper(function):
        test_vectors = []
        test_vector = {
            "file": Path(filename).name
        }

        with open(filename, 'r') as f:

            line_num = 1

            for line in f.readlines():
                if m := re.match(r"^(\w+)\s*=\s*(\w+)", line):

                    if "line" not in test_vector:
                        test_vector["line"] = line_num

                    key = m.group(1)
                    test_vector[key] = m.group(2)

                    if key == "MD":
                        test_vectors.append(test_vector)

                        # The MD of the previous test vector is used as the
                        # seed to the next one.

                        test_vector = {
                            "Seed": test_vector["MD"],
                            "file": Path(filename).name
                        }

        function.tc_cases = [tuple((tv[p] for p in params)) for tv in test_vectors]
        function.tc_params = tc_params

        return function
    return wrapper

def load_wycheproof_test_vectors(filename):
    """
    PyTest decorator to load test vectors from Project Wycheproof's JSON
    test vector files to parameterize the test.

        Parameters:
            tc_params: A string containing a comma-separated list of
                       keys to pick from each test vector from the file.
                       For example: "key, msg, tag"
            filename: The name of the JSON test vector file to load.
    """
    def wrapper(function):
        with open(filename, 'r') as f:
            json_data = json.load(f)

            function.tc_cases = []
            function.tc_params = "test_vector"

            for group in json_data["testGroups"]:
                function.tc_cases += group["tests"]

        return function
    return wrapper