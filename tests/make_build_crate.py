#!/usr/bin/python3

"""Generate an Alire manifest and GPR file to aggregate the test suite
under a specific configuration.
"""

import argparse
import os
import os.path
from pathlib import Path
import sys
import textwrap
from typing import Dict, List, Any

import toml

# The Tux configuration is a mapping of the variable name (e.g. "SHA1_Backend")
# to its value (e.g. "Enabled")
TuxConfig = Dict[str, str]


# Paths to the test suites are found relative to the location of this script
_this_file_dir = Path(os.path.realpath(os.path.dirname(__file__)))


def escaped_abs_path(path: Path) -> str:
    """Convert a path to a string and escape backslash characters"""
    return str(path.absolute()).replace("\\", "\\\\")


def list_kat_programs() -> List[Path]:
    """Get a list of all the test driver subdirectories in the kat/programs/ directory.

    This allows for automatic discovery of new KAT programs when they are added.
    """
    programs_dir = Path(_this_file_dir / "kat" / "programs")
    return [subdir for subdir in programs_dir.iterdir() if subdir.is_dir()]


def get_project_files() -> List[Path]:
    """Get a list of the paths to all GPR files in the test suite"""

    # First, get a list of paths to the various test program directories.

    # All test drivers for the KAT suite are stored in individual subdirectories
    # under kat/programs/
    programs_dir = Path(_this_file_dir / "kat" / "programs")
    project_dirs = [subdir for subdir in programs_dir.iterdir() if subdir.is_dir()]

    # Other test program directories
    project_dirs.append(_this_file_dir / "benchmark")
    project_dirs.append(_this_file_dir / "unit_tests")

    # Get all GPR files in the project directories
    gpr_files = []
    for dir in project_dirs:
        gpr_files += [
            file for file in dir.iterdir() if file.is_file() and file.suffix == ".gpr"
        ]

    return gpr_files


def get_alire_config_variables(alire_toml: Path) -> Dict[str, Dict[str, Any]]:
    """Get a list of the configuration variables from an Alire TOML file"""

    result = {}
    data = toml.load(alire_toml)
    if "configuration" in data:
        config = data["configuration"]
        if "variables" in config:
            result = config["variables"]

    return result


def gen_alire_toml(
    config: TuxConfig,
    tux_build_profile: str,
    coverage: bool,
    prove: bool,
    unit_tests_report_format: str,
) -> str:
    """Generate an aggregate alire.toml crate with the specified Tux config."""
    test_projs = get_project_files()

    # All test projects use the validation build profile by default
    test_proj_build_profile = {proj.stem: "validation" for proj in test_projs}

    # Use the same build profile as the Tux crate for the benchmark
    # This ensures that the benchmark is built in release mode when Tux is
    # also built in release mode.
    test_proj_build_profile["benchmark"] = tux_build_profile

    # Only include these dependencies when requested to minimise setup time
    gnatcov_dep = 'gnatcov = "^22.0.1"' if coverage else ""
    gnatprove_dep = 'gnatprove = "=12.1.1"' if prove else ""

    return textwrap.dedent(
        f"""
        name = "test_config"
        description = "Crate to build the test suite for a specific test configuration"
        version = "0.1.0-dev"

        authors = ["Daniel King"]
        maintainers = ["Daniel King <damaki.gh@gmail.com>"]
        maintainers-logins = ["damaki"]

        [[depends-on]]
        tux = "*"
        unit_tests = "*"
        {gnatcov_dep}
        {gnatprove_dep}

        [[pins]]
        tux = {{ path = "{escaped_abs_path(_this_file_dir.parent)}" }}
        """
        + "\n        ".join(
            [
                f'{x.stem} = {{ path = "{escaped_abs_path(x.parent)}" }}'
                for x in test_projs
            ]
        )
        + f"""

        [build-profiles]
        tux = "{tux_build_profile}"
        """
        + "\n        ".join(
            [f'{x.stem} = "{test_proj_build_profile[x.stem]}"' for x in test_projs]
        )
        + """

        [configuration.values]
        """
        + "\n        ".join(f"tux.{name} = {value}" for name, value in config.items())
        + f"""\n        unit_tests.Report_Format = "{unit_tests_report_format}" """
    )


def gen_aggregate_test_project() -> str:
    """Generate a GPR file that aggregates all the test suite executables"""
    return (
        "aggregate project Test_Config is\n"
        + "   for Project_Files use (\n"
        + "      "
        + ",\n      ".join([f'"{x.absolute()}"' for x in get_project_files()])
        + ");\n"
        + "end Test_config;\n"
    )


def create_test_config_crate(
    build_crate_dir: Path,
    config: TuxConfig,
    tux_build_profile: str,
    coverage: bool,
    prove: bool,
    unit_tests_report_format: str,
) -> None:
    """Create a test configuration crate in the specified directory.

    This creates an alire.toml and test_config.gpr file in the specified
    directory. Running "alr build" in that directory will build the test suite
    with the specified Tux crate configuration.
    """
    os.makedirs(build_crate_dir, exist_ok=True)

    with open(
        os.path.join(build_crate_dir, "alire.toml"), "w", encoding="utf8"
    ) as toml_file:
        toml_file.write(
            gen_alire_toml(
                config, tux_build_profile, coverage, prove, unit_tests_report_format
            )
        )

    with open(
        os.path.join(build_crate_dir, "test_config.gpr"), "w", encoding="utf8"
    ) as gpr_file:
        gpr_file.write(gen_aggregate_test_project())


def parse_args(tux_config_vars: Dict[str, Dict[str, Any]]):
    """Parse the script's arguments

    :param tux_config_vars: The crate config variables loaded from the Alire TOML
    """
    parser = argparse.ArgumentParser("Run the Tux test suites")

    for name in tux_config_vars.keys():
        var_type = tux_config_vars[name]["type"]
        if var_type == "Enum":
            parser.add_argument(
                f"--{name}".lower().replace("_", "-"),
                type=str,
                action="store",
                choices=tux_config_vars[name]["values"],
                default=tux_config_vars[name]["default"],
                help=f"Crate configuration value to use for Tux.{name}",
            )
        elif var_type == "Boolean":
            parser.add_argument(
                f"--{name}".lower().replace("_", "-"),
                type=str,
                action="store",
                choices=["True", "False"],
                default="True" if tux_config_vars[name]["default"] else "False",
                help=f"Crate configuration value to use for Tux.{name}",
            )
        else:
            print(
                (
                    f"Unsupported crate configuration variable type '{var_type}' "
                    f"for variable '{name}'"
                ),
                file=sys.stderr,
            )
            sys.exit(-1)

    parser.add_argument(
        "--coverage", action="store_true", help="Include dependency on GNATcoverage"
    )
    parser.add_argument(
        "--prove", action="store_true", help="Include dependency on GNATprove"
    )
    parser.add_argument(
        "--tux-build-profile",
        nargs="?",
        choices=["development", "validation", "release"],
        default="validation",
        help="Alire build profile to use when building Tux",
    )
    parser.add_argument(
        "-o",
        "--output-dir",
        nargs="?",
        default="test_crate",
        type=str,
        help="Output directory for the generated aggregate crate",
    )
    parser.add_argument(
        "--unit-tests-report-format",
        choices=["Text", "XML"],
        default="Text",
        help="Set the output format for the unit tests",
    )

    return parser.parse_args()


def config_value_repr(value, type):
    """Get the string representation of a crate configuration value

    Boolean types will have their value unquoted and lowercase. E.g. true and false.
    Enum types will have their value quoted. E.g. "Size" and "Speed".

    """
    if type == "Boolean":
        return value.lower()
    else:
        return f'"{value}"'


def _main():
    tux_config_vars = get_alire_config_variables(_this_file_dir.parent / "alire.toml")

    args = parse_args(tux_config_vars)

    args_vars = vars(args)
    tux_config_values = {
        name: config_value_repr(args_vars[name.lower()], tux_config_vars[name]["type"])
        for name in tux_config_vars.keys()
    }

    create_test_config_crate(
        build_crate_dir=Path(args.output_dir),
        config=tux_config_values,
        tux_build_profile=args.tux_build_profile,
        coverage=args.coverage,
        prove=args.prove,
        unit_tests_report_format=args.unit_tests_report_format,
    )


if __name__ == "__main__":
    sys.exit(_main())
