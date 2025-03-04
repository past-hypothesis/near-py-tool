Minimal build/deploy tool for Python NEAR smart contracts
=========================================================

This is a work-in-progress build/deploy tool for Python NEAR smart contracts.

Python source files are compiled into the WASM binary via [MicroPython](https://github.com/micropython/micropython) and [Emscripten](https://emscripten.org/docs/getting_started/downloads.html) and then deployed via `near-cli-rs` tool.

`near-py-tool` CLI is modelled after [cargo-near](https://github.com/near/cargo-near) with most of the 
command-line options compatible (not all are implemented yet).


Dependencies
------------

`near-py-tool` expects the following dependencies installed:
- Python>=3.9
- essential build tools like `make` and C compiler
- [Emscripten](https://emscripten.org/docs/getting_started/downloads.html) for compiling Python into WASM via MicroPython (can be installed automatically by `near-py-tool`, if desired). Version 4.0.0 or above is recommended as there are issues with building some contracts on 3.x
- [near-cli-rs](https://github.com/near/near-cli-rs) for NEAR Protocol interactions


Platform support
----------------

Currenly Linux, MacOS and Windows (native/MSYS2/WSL) platforms are supported


Python library support
----------------------

Most of the MicroPython standard library is included and should be functional where applicable to WASM runtime environment.

External Python package are supported as long as they don't require native compiled code to work. `near-py-tool` will download any packages referenced
via `pyproject.toml` and will try to compile them into the WASM binary alongside the main `contract.py` file.

Unneeded modules from the MicroPython stdlib can be excluded from the build by adding the following section to `pyproject.toml`:
    [tool.near-py-tool]
    exclude-micropython-stdlib-packages = [...]


NEAR WASM ABI support
----------------

Everything from https://github.com/near/near-sdk-rs/blob/master/near-sys/src/lib.rs should be available via `near` module, for example:

- `near.input()` retrieves contract input as `bytes`
- `near.value_return(value)` returns a value (`str` or `bytes`) from the contract
- `near.log_utf8(message)` logs a message (`str`)

Contract methods to be exported from the WASM binary should be decorated with `@near.export`

See the [NEAR-ABI.md](NEAR-ABI.md) for a complete list of available methods and their type signatures.


Benchmarks
----------

See [GAS-PROFILE-REPORT.md](GAS-PROFILE-REPORT.md) for gas statistics from the test runs

Stats for similar Rust/JS contracts are available [here](https://github.com/near/near-sdk-js/tree/develop/benchmark)


Getting started
---------------

- install `near-py-tool` via `pip install near-py-tool`
- run `near-py-tool new test-project` to create a minimal Python smart contract project
- `cd ./test-project`
- run `near-py-tool build` to produce a standalone WASM file
- run `near-py-tool create-dev-account` to create a testnet account if you don't have one already
- run `near-py-tool deploy` to deploy the smart contract

Examples
--------

While there is still plenty of work ahead of us, there are already some small yet useful apps implemented using this project:

- The smart contract that guards 3000 NEAR and gives away 2 NEAR per user and prevents double-spend: https://github.com/frol/1t-agents-fundme-agent
- The smart contract that guards 50 NEAR until it is jailbreaked: https://github.com/frol/neardevnewsletter-issue50-quest/tree/main/contract
- Demo Web4 contract in Python: https://github.com/frol/near-web4-demo-py
- Experimental ports of fungible/non-fungible token contracts as a part of the test suite: https://github.com/past-hypothesis/near-py-tool/blob/main/near_py_tool/tests/fungible_token.py https://github.com/past-hypothesis/near-py-tool/blob/main/near_py_tool/tests/non_fungible_token.py

TODO
----

- NEAR ABI metadata generation
- reproducible builds
