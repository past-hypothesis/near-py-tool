import ast
import base64
import json
import os
import re
import shutil
import sys
from importlib.resources import files
from pathlib import Path
from typing import Set

import click
import requests
import toml

import near_py_tool.api as api
from near_py_tool.run_command import (
    check_build_dependencies,
    check_deploy_dependencies,
    is_command_available,
    run_build_command,
    run_command,
)


def get_near_exports_from_file(file_path: str) -> Set[str]:
    """
    Extract function names decorated with NEAR export decorators from a Python file.
    This includes direct near.export decorators and custom decorators that wrap near.export.
    
    Args:
        file_path: Path to the Python file to analyze
        
    Returns:
        Set of function names that are exported to the NEAR blockchain
    """
    with open(file_path, "r") as file:
        content = file.read()
        tree = ast.parse(content, filename=file_path)

    # Track custom decorators that eventually use near.export
    custom_exporters = set(["export", "view", "call", "init", "callback"])
    # Track functions that are exported
    near_exports = set()
    
    # First pass: identify custom decorators that use near.export
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            # Check if this is a potential custom decorator function
            if node.name in custom_exporters:
                for body_node in ast.walk(node):
                    # Check function bodies for return statements that use near.export
                    if isinstance(body_node, ast.Return) and body_node.value is not None:
                        # Look for near.export in the return expression
                        for return_node in ast.walk(body_node.value):
                            if (isinstance(return_node, ast.Attribute) and 
                                isinstance(return_node.value, ast.Name) and 
                                return_node.value.id == "near" and 
                                return_node.attr == "export"):
                                custom_exporters.add(node.name)
                                break
    
    # Second pass: find functions with near.export or custom exporters as decorators
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            for decorator in node.decorator_list:
                print(decorator.__dict__)
                #print(decorator.id)

                # Case 1: Direct @near.export
                if ((isinstance(decorator, ast.Attribute) and 
                     isinstance(decorator.value, ast.Name) and 
                     decorator.value.id == "near" and 
                     decorator.attr == "export") or
                    (isinstance(decorator, ast.Name) and 
                     decorator.id == "near.export")):
                    near_exports.add(node.name)
                    break

                # Case 2: Using a custom exporter decorator like @init, @view, etc.
                if isinstance(decorator, ast.Name) and decorator.id in custom_exporters:
                    near_exports.add(node.name)
                    break
    
    return near_exports



def get_imports_from_file(file_path):
    """Extract imported modules from a Python file."""
    with open(file_path, "r") as file:
        tree = ast.parse(file.read(), filename=file_path)

    imports = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imports.add(alias.name)
        elif isinstance(node, ast.ImportFrom):
            module = node.module
            if module:
                imports.add(module)

    return imports


def has_compiled_extensions(package_name, package_path):
    native_library_paths = []
    for ext in ["so", "pyd", "dll", "dylib"]:
        native_library_paths.append(package_path.rglob(f"*.{ext}"))
    return len(native_library_paths) == 0


def is_mpy_module(name):
    mpy_modules = ["array", "builtins", "json", "os", "random", "struct", "sys"]
    return name in mpy_modules


def is_mpy_lib_package(name):
    mpy_lib_packages = ["aiohttp", "cbor2", "iperf3", "pyjwt", "requests"]
    return name in mpy_lib_packages


mpy_stdlib_packages = [
    "binascii",
    "contextlib",
    "fnmatch",
    "hashlib-sha224",
    "hmac",
    "keyword",
    "os-path",
    "pprint",
    "stat",
    "tempfile",
    "types",
    "warnings",
    "__future__",
    "bisect",
    "copy",
    "functools",
    "hashlib-sha256",
    "html",
    "locale",
    "pathlib",
    "quopri",
    "string",
    "textwrap",
    "unittest",
    "zlib",
    "abc",
    "cmd",
    "curses.ascii",
    "gzip",
    "hashlib-sha384",
    "inspect",
    "logging",
    "pickle",
    "random",
    "struct",
    "threading",
    "unittest-discover",
    "argparse",
    "collections",
    "datetime",
    "hashlib",
    "hashlib-sha512",
    "io",
    "operator",
    "pkg_resources",
    "shutil",
    "tarfile",
    "time",
    "uu",
    "base64",
    "collections-defaultdict",
    "errno",
    "hashlib-core",
    "heapq",
    "itertools",
    "os",
    "pkgutil",
    "ssl",
    "tarfile-write",
    "traceback",
    "venv",
]

near_module_name = "near"


def is_external_package(name):
    return (
        not is_mpy_module(name)
        and not is_mpy_lib_package(name)
        and name not in mpy_stdlib_packages
        and name != near_module_name
    )


def generate_manifest(contract_path, package_paths, manifest_path, excluded_stdlib_packages):
    with open(manifest_path, "w") as o:
        o.write("# THIS FILE IS GENERATED, DO NOT EDIT\n\n")
        for module in mpy_stdlib_packages:
            if module not in excluded_stdlib_packages:
                o.write(f'require("{module}")\n')
        for mod in ["typing", "typing_extensions"]:
            o.write(f'module("{mod}.py", base_path="$(PORT_DIR)/extra/typing")\n')
        for module, path in package_paths.items():
            if is_mpy_lib_package(module):
                o.write(f'require("{module}")\n')
            elif not is_mpy_module(module):
                base_path = str(path.parent.relative_to(manifest_path.parent)).replace("\\", "/")
                o.write(f'package("{module}", base_path="{base_path}")\n')
        o.write(f'module("{contract_path.name}", base_path="..")\n')


def generate_export_wrappers(contract_path, exports, export_wrappers_path):
    with open(export_wrappers_path, "w") as o:
        o.write("/* THIS FILE IS GENERATED, DO NOT EDIT */\n\n")
        o.write("void run_frozen_fn(const char *file_name, const char *fn_name);\n\n")
        for export in exports:
            o.write(f'void {export}() \u007b\n  run_frozen_fn("{contract_path.name}", "{export}");\n\u007d\n\n')


def get_venv_package_paths(file_path, venv_path):
    """Get paths of all packages imported by a Python file."""
    imports = get_imports_from_file(file_path)
    package_paths = {}
    glob_pattern_base = (
        "lib/site-packages" if (venv_path / "lib" / "site-packages").is_dir() else "lib/python*.*/site-packages"
    )
    for module_name in imports:
        if is_external_package(module_name):
            paths = list(venv_path.glob(f"{glob_pattern_base}/{module_name}"))
            if len(paths) == 0:
                click.echo(
                    f"Warning: module {module_name} path wasn't resolved; is it installed in the current venv at {venv_path}?"
                )
            elif len(paths) > 1:
                click.echo(f"Warning: module {module_name} has multiple candidate paths: {paths}")
            for path in paths:
                package_paths[module_name] = path
    return package_paths


def get_excluded_stdlib_packages(project_path):
    pyproject_path = project_path / "pyproject.toml"
    if pyproject_path.is_file():
        with open(pyproject_path, "r") as file:
            pyproject_data = toml.load(file)
        return pyproject_data.get("tool", {}).get("near-py-tool", {}).get("exclude-micropython-stdlib-packages", [])
    else:
        return []


def install_pyproject_dependencies(project_path, venv_path):
    pyproject_path = project_path / "pyproject.toml"
    if pyproject_path.is_file():
        with open(pyproject_path, "r") as file:
            pyproject_data = toml.load(file)
        for package in pyproject_data.get("project", {}).get("dependencies", {}):
            click.echo(f"Installing {package} into {venv_path}...")
            pip_path = None
            for path in [
                venv_path / "bin" / "pip",
                venv_path / "bin" / "pip.exe",
                venv_path / "Scripts" / "pip.exe",
            ]:
                if path.is_file():
                    pip_path = path
            if pip_path is None:
                click.echo(
                    click.style(
                        f"Error: build Python venv doesn't have pip installed",
                        fg="bright_red",
                    )
                )
                sys.exit(1)
            run_command(
                [pip_path, "install", package, "--disable-pip-version-check"],
                cwd=project_path,
            )


def build(
    project_dir,
    rebuild_all,
    contract_name="contract.py",
    install_dependencies_silently=False,
):
    project_path = Path(project_dir).resolve()
    project_name = project_path.name
    build_path = project_path / "build"
    mpy_cross_build_path = project_path / "build" / "mpy-cross"
    venv_path = build_path / ".venv"
    mpy_cross_path = files("near_py_tool") / "assets" / "micropython" / "mpy-cross"
    mpy_port_path = files("near_py_tool") / "assets" / "micropython" / "ports" / "webassembly-near"
    contract_path = project_path / contract_name
    if not contract_path.is_file():
        click.echo(click.style(f"Error: contract file {contract_path} doesn't exist", fg="bright_red"))
        sys.exit(1)

    if rebuild_all:
        click.echo(f"Removing build directory {build_path} to perform a clean build")
        try:
            shutil.rmtree(build_path)
        except Exception:
            pass

    build_path.mkdir(parents=True, exist_ok=True)

    check_build_dependencies(build_path, install_dependencies_silently=install_dependencies_silently)

    # click.echo(f"Running `uv sync` in {project_path}...")
    # run_build_command(build_path, ['uv', "sync"], cwd=project_path)

    if not venv_path.is_dir():
        click.echo(f"Creating a venv in {venv_path}...")
        run_command(
            [
                "python" if is_command_available("python") else "python3",
                "-m",
                "venv",
                venv_path,
            ],
            cwd=project_path,
        )

    install_pyproject_dependencies(project_path, venv_path)

    package_paths = get_venv_package_paths(contract_path, venv_path)

    for module, path in package_paths.items():
        if has_compiled_extensions(module, path):
            click.echo(
                click.style(
                    f"Warning: required module {module} at {path} has compiled extensions and might not work correctly in WASM environment",
                    fg="bright_red",
                )
            )

    exports = list(get_near_exports_from_file(contract_path))
    click.echo(f"The contract WASM will export the following methods: {exports}")

    excluded_stdlib_packages = get_excluded_stdlib_packages(project_path)
    print(f"Excluding the following MicroPython stdlib packages from the build: {excluded_stdlib_packages}")
    print(
        f"(this list can be adjusted via [tool.near-py-tool] exclude-micropython-stdlib-packages setting in pyproject.toml)"
    )

    generate_manifest(
        contract_path,
        package_paths,
        build_path / "manifest.py",
        excluded_stdlib_packages,
    )
    generate_export_wrappers(contract_path, exports, build_path / "export_wrappers.c")
    try:
        os.unlink(build_path / "frozen_content.c")  # force frozen content rebuilt every time
    except Exception:
        pass

    contract_wasm_path = build_path / Path(
        contract_name if contract_name != "contract.py" else project_name
    ).with_suffix(".wasm")
    run_build_command(
        build_path,
        ["make", "-C", mpy_cross_path, f"BUILD={mpy_cross_build_path}"],
        cwd=project_path,
    )
    run_build_command(
        build_path,
        [
            "make",
            "-C",
            mpy_port_path,
            f"BUILD={build_path}",
            f"MICROPY_MPYCROSS={mpy_cross_build_path}/mpy-cross",
            f"MICROPY_MPYCROSS_DEPENDENCY={mpy_cross_build_path}/mpy-cross",
            f"FROZEN_MANIFEST={build_path / 'manifest.py'}",
            f"SRC_C_GENERATED={build_path / 'export_wrappers.c'}",
            f"EXPORTED_FUNCTIONS={','.join(['_' + e for e in exports])}",
            f"OUTPUT_WASM={contract_wasm_path}",
        ],
        cwd=project_path,
    )

    click.echo(f"Contract WASM file was build successfully and is located at {contract_wasm_path}")

    return contract_wasm_path


def is_account_id_available(account_id, network):
    return (
        run_command(
            [
                "near",
                "account",
                "view-account-summary",
                account_id,
                "network-config",
                network,
                "now",
            ],
            check=False,
        )
        != 0
    )


def create_account(account_id, extra_args, install_dependencies_silently=False):
    check_deploy_dependencies(install_dependencies_silently=install_dependencies_silently)
    cmdline = [
        "near",
        "account",
        "create-account",
        "sponsor-by-faucet-service",
        account_id,
    ]
    cmdline.extend([str(arg) for arg in extra_args])
    run_command(cmdline)
    return account_id


def transfer_amount(from_account_id, to_account_id, amount):
    run_command(["near", "send", from_account_id, to_account_id, str(amount)])


def deploy(
    project_dir,
    rebuild_all=False,
    account_id="*",
    extra_args=[],
    contract_name="contract.py",
    install_dependencies_silently=False,
):
    check_deploy_dependencies(install_dependencies_silently=install_dependencies_silently)
    project_path = Path(project_dir).resolve()
    project_name = project_path.name
    wasm_path = (
        project_path
        / "build"
        / Path(contract_name if contract_name != "contract.py" else project_name).with_suffix(".wasm")
    )
    build(
        project_path,
        rebuild_all,
        contract_name=contract_name,
        install_dependencies_silently=install_dependencies_silently,
    )
    if account_id == "*":
        account_id = local_keychain_account_ids()[0]
    cmdline = ["near", "contract", "deploy", account_id, "use-file", wasm_path]
    cmdline.extend([str(arg) for arg in extra_args])
    run_command(cmdline, cwd=project_path)


def local_keychain_account_ids():
    try:
        accounts_path = Path("~/.near-credentials/accounts.json").expanduser().resolve()
        with open(accounts_path, "r") as f:
            d = json.load(f)
            return [v["account_id"] for v in d]
    except:
        pass


def get_tx_data(tx_id, account_id):
    headers = {"Content-Type": "application/json"}
    data = {
        "jsonrpc": "2.0",
        "id": "dontcare",
        "method": "tx",
        "params": [tx_id, account_id],
    }
    response = requests.post("https://rpc.testnet.near.org", headers=headers, json=data).json()
    success_value = base64.b64decode(response.get("result", {}).get("status", {}).get("SuccessValue", ""))
    success_receipt_id = (
        response.get("result", {})
        .get("transaction_outcome", {})
        .get("outcome", {})
        .get("status", {})
        .get("SuccessReceiptId", "")
    )
    success_receipt = next(
        (d for d in response.get("result", {}).get("receipts_outcome", {}) if d.get("id") == success_receipt_id),
        {},
    )
    gas_burnt = success_receipt.get("outcome", {}).get("gas_burnt", 0)
    gas_profile = {
        cost["cost"]: cost["gas_used"]
        for cost in success_receipt.get("outcome", {}).get("metadata", {}).get("gas_profile", {})
    }
    return success_value, gas_burnt, gas_profile


def format_gas(gas):
    if gas >= 1e12:
        return f"{(gas / 1e12):.2f}T"
    else:
        return f"{(gas / 1e9):.2f}G"


def call_method(
    account_id,
    method_name,
    input,
    attached_deposit="0 NEAR",
    install_dependencies_silently=False,
):
    check_deploy_dependencies(install_dependencies_silently=install_dependencies_silently)
    if isinstance(input, dict) or isinstance(input, list):
        args_type = "json-args"
        args = json.dumps(input)
    elif isinstance(input, str):
        args_type = "text-args"
        args = input
    else:
        args_type = "base64-args"
        args = base64.b64encode(input)
    cmdline = [
        "near",
        "contract",
        "call-function",
        "as-transaction",
        account_id,
        method_name,
        args_type,
        args,
        "prepaid-gas",
        "300 Tgas",
        "attached-deposit",
        attached_deposit,
        "sign-as",
        account_id,
        "network-config",
        "testnet",
        "sign-with-legacy-keychain",
        "send",
    ]
    exit_code, stdout, stderr = run_command(cmdline, capture_output=True)
    print(stderr)
    tx_id = re.search(r"Transaction ID: (\w+)", stderr).group(1)
    result, gas_burnt, gas_profile = get_tx_data(tx_id, account_id)
    with open(f"gas-profile-report.md", "a") as f:
        f.write(f"## `near-py-tool` test run gas statistics\n")
        f.write(f"### {method_name}({input})\n")
        f.write(f"- Gas used to execute the receipt (actual contract call): `{format_gas(gas_burnt)}`\n")
        for k, v in gas_profile.items():
            f.write(f"  - `{k}`: `{format_gas(int(v))}`\n")
    return result, gas_burnt, gas_profile
