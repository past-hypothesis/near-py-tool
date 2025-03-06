Minimal build/deploy tool for Python NEAR smart contracts
=========================================================

This is a build/deploy tool for Python NEAR smart contracts for https://github.com/near/devtools/issues/2

Python source files are compiled into the WASM binary via [MicroPython](https://github.com/micropython/micropython) and [Emscripten](https://emscripten.org/docs/getting_started/downloads.html) and then deployed via `near-cli-rs` tool.

`near-py-tool` CLI is modelled after [cargo-near](https://github.com/near/cargo-near)


Dependencies
------------

`near-py-tool` expects the following dependencies installed:
- Python>=3.9
- essential build tools like `make` and C compiler
- [Emscripten](https://emscripten.org/docs/getting_started/downloads.html) for compiling Python into WASM via MicroPython (can be installed automatically by `near-py-tool`, if desired). Version 4.0.0 or above is recommended as there are issues with building some of the contracts on 3.x. Automatic installation via `emsdk` is offered if `emcc` is absent from PATH
- [near-cli-rs](https://github.com/near/near-cli-rs) for deployment and other NEAR Protocol interactions


Getting started
---------------

- install `near-py-tool` via `pip install near-py-tool`
- run `near-py-tool new test-project` to create a minimal Python smart contract project
- `cd ./test-project`
- run `near-py-tool build` to produce a standalone WASM file
- run `near-py-tool create-dev-account` to create a testnet account if you don't have one already
- run `near-py-tool deploy` to deploy the smart contract to testnet or mainnet

Examples
--------

Please see the [test suite](https://github.com/past-hypothesis/near-py-tool/blob/main/near_py_tool/tests) for various low-level NEAR API usage examples:
- deploy_contract.py / promise_api.py - building and deploying a dependent contract with promises via promise_batch_action_deploy_contract()
- lowlevel_api.py - minimal storage api usage example
- fungible_token.py - low-level API port of https://github.com/near/near-sdk-rs/tree/master/near-contract-standards/src/fungible_token contract
- non_fungible_token.py - low-level API port of https://github.com/near/near-sdk-rs/tree/master/near-contract-standards/src/non_fungible_token contract

External examples:
- The smart contract that guards 3000 NEAR and gives away 2 NEAR per user and prevents double-spend: https://github.com/frol/1t-agents-fundme-agent
- The smart contract that guards 50 NEAR until it is jailbreaked: https://github.com/frol/neardevnewsletter-issue50-quest/tree/main/contract
- Demo Web4 contract in Python: https://github.com/frol/near-web4-demo-py


Platform support
----------------

Currenly Linux, MacOS and Windows (native/MSYS2/WSL) platforms are supported. Native Windows support is implemented via an automatically installed MSYS2 local copy which is utilized for MicroPython/WASM contract builds


Python library support / compatibility
--------------------------------------

Most of the MicroPython standard library is included and should be functional where applicable to WASM runtime environment.

External Python package are supported as long as they don't require native compiled code to work. `near-py-tool` will download any packages referenced
via `pyproject.toml` and will try to compile them into the WASM binary alongside the main `contract.py` file.

Unneeded modules from the MicroPython stdlib can be excluded from the build by adding the following section to `pyproject.toml`:
    [tool.near-py-tool]
    exclude-micropython-stdlib-packages = [...]

Please be aware that there is no full compatibility to CPython yet since we use MicroPython as a runtime


NEAR WASM ABI support
---------------------

Everything from https://github.com/near/near-sdk-rs/blob/master/near-sys/src/lib.rs should be available via `near` module, for example:

- `near.input()` retrieves contract input as `bytes`
- `near.value_return(value)` returns a value (`str` or `bytes`) from the contract
- `near.log_utf8(message)` logs a message (`str`)

Contract methods to be exported from the WASM binary should be decorated with `@near.export`

See the [NEAR-ABI.md](NEAR-ABI.md) for a complete list of available methods and their type signatures.


Benchmarks
----------

[Here](GAS-PROFILE-REPORT.md) are some gas cost benchmark results which allow comparison to Rust and JS

Stats for similar Rust/JS contracts are available [here](https://github.com/near/near-sdk-js/tree/develop/benchmark)

In general, gas costs for this Python implementation lie in between the Rust and JS values, which makes Python smart contracts practical for most use cases


Contributing
------------

We are in the process of restructuring this into separate Python SDK / nearc compiler / test suite repositories as part of https://github.com/near/devtools/issues/3, so future contributions should be directed towards the new repositories as they take shape

