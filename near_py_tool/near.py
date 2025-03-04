from pathlib import Path

import randomname

import near_py_tool.api as api


def test_method(contract_path, method_name, input, attached_deposit="0 NEAR", skip_deploy=False):
    """
    Builds & deploys the smart contract from the current python file and then calls the specified method with the specified input
    :param name: method name
    :param input: method call input, can be json/string/bytes
    :return: (method return value, gas burnt, full call transaction metadata) tuple
    This is no-op in the modnear.c implementation which gets compiled into WASM file
    """
    account_id = api.local_keychain_account_ids()[0]
    if not skip_deploy:
        print(f"Path(contract_path): {Path(contract_path)} Path(contract_path).name: {Path(contract_path).name}")
        api.deploy(
            Path(contract_path).parent,
            account_id=account_id,
            contract_name=Path(contract_path).name,
            extra_args=[
                "without-init-call",
                "network-config",
                "testnet",
                "sign-with-legacy-keychain",
                "send",
            ],
            install_dependencies_silently=True,
        )
    result, gas_burnt, gas_profile = api.call_method(
        account_id, method_name, input, attached_deposit=attached_deposit, install_dependencies_silently=True
    )
    print(f"test_method({contract_path}, {method_name}, {input}):")
    print(f"  result: {result}")
    print(f"  gas_burnt: {gas_burnt / 1e12} Tgas")
    print(f"  gas_profile: {gas_profile}")
    return result, gas_burnt


def build_contract(contract_path):
    """
    Compiles `contract_path` into WASM file in the `build` directory with .py extension replaced with .wasm
    """
    return api.build(
        Path(contract_path).parent,
        rebuild_all=False,
        contract_name=Path(contract_path).name,
        install_dependencies_silently=True,
    )


def test_add_extra_balance():
    """
    Adds extra balance to the test account
    """
    prev_account_id = api.create_account(
        f"{randomname.get_name()}.testnet",
        ["autogenerate-new-keypair", "save-to-legacy-keychain", "network-config", "testnet", "create"],
    )
    new_account_id = api.create_account(
        f"{randomname.get_name()}.testnet",
        ["autogenerate-new-keypair", "save-to-legacy-keychain", "network-config", "testnet", "create"],
    )
    api.transfer_amount(prev_account_id, new_account_id, 9.9)
    return api.local_keychain_account_ids()[0]


def test_create_account():
    """
    Creates a new dev account
    """
    api.create_account(
        f"{randomname.get_name()}.testnet",
        ["autogenerate-new-keypair", "save-to-legacy-keychain", "network-config", "testnet", "create"],
    )
    return api.local_keychain_account_ids()[0]


def test_account_id():
    """
    Returns account id the test is running under
    """
    return api.local_keychain_account_ids()[0]


# Mock implementation of the MicroPython C module
def export(fn):
    """
    NEAR exported method decorator (no-op here)
    """
    return fn


# Registers
def read_register(register_id):
    """
    Mock function for near_read_register.
    :param register_id: Register ID.
    :return: Placeholder bytes.
    """
    return b""


def read_register_as_str(register_id):
    """
    Mock function for near_read_register_as_str.
    :param register_id: Register ID.
    :return: Placeholder string.
    """
    return ""


def register_len(register_id):
    """
    Mock function for near_register_len.
    :param register_id: Register ID.
    :return: Placeholder integer.
    """
    return 0


def write_register(register_id, data):
    """
    Mock function for near_write_register.
    :param register_id: Register ID.
    :param data: Data to write.
    """
    pass


# Context API
def current_account_id():
    """
    Mock function for near_current_account_id.
    :return: Placeholder string.
    """
    return ""


def signer_account_id():
    """
    Mock function for near_signer_account_id.
    :return: Placeholder string.
    """
    return ""


def signer_account_pk():
    """
    Mock function for near_signer_account_pk.
    :return: Placeholder bytes.
    """
    return b""


def predecessor_account_id():
    """
    Mock function for near_predecessor_account_id.
    :return: Placeholder string.
    """
    return ""


def input():
    """
    Mock function for near_input.
    :return: Placeholder bytes.
    """
    return b""


def input_as_str():
    """
    Mock function for near_input_as_str.
    :return: Placeholder string.
    """
    return ""


def block_height():
    """
    Mock function for near_block_height.
    :return: Placeholder integer.
    """
    return 0


def block_timestamp():
    """
    Mock function for near_block_timestamp.
    :return: Placeholder integer.
    """
    return 0


def epoch_height():
    """
    Mock function for near_epoch_height.
    :return: Placeholder integer.
    """
    return 0


def storage_usage():
    """
    Mock function for near_storage_usage.
    :return: Placeholder integer.
    """
    return 0


# Economics API
def account_balance():
    """
    Mock function for near_account_balance.
    :return: Placeholder integer.
    """
    return 0


def account_locked_balance():
    """
    Mock function for near_account_locked_balance.
    :return: Placeholder integer.
    """
    return 0


def attached_deposit():
    """
    Mock function for near_attached_deposit.
    :return: Placeholder integer.
    """
    return 0


def prepaid_gas():
    """
    Mock function for near_prepaid_gas.
    :return: Placeholder integer.
    """
    return 0


def used_gas():
    """
    Mock function for near_used_gas.
    :return: Placeholder integer.
    """
    return 0


# Math API
def random_seed():
    """
    Mock function for near_random_seed.
    :return: Placeholder bytes.
    """
    return b""


def sha256(value):
    """
    Mock function for near_sha256.
    :param value: Input value.
    :return: Placeholder bytes.
    """
    return b""


def keccak256(value):
    """
    Mock function for near_keccak256.
    :param value: Input value.
    :return: Placeholder bytes.
    """
    return b""


def keccak512(value):
    """
    Mock function for near_keccak512.
    :param value: Input value.
    :return: Placeholder bytes.
    """
    return b""


def ripemd160(value):
    """
    Mock function for near_ripemd160.
    :param value: Input value.
    :return: Placeholder bytes.
    """
    return b""


def ecrecover(hash, sig, v, malleability_flag):
    """
    Mock function for near_ecrecover.
    :param hash: Hash value.
    :param sig: Signature.
    :param v: Recovery ID.
    :param malleability_flag: Malleability flag.
    :return: Placeholder bytes.
    """
    return b""


def ed25519_verify(sig, msg, pub_key):
    """
    Mock function for near_ed25519_verify.
    :param sig: Signature.
    :param msg: Message.
    :param pub_key: Public key.
    :return: Placeholder boolean.
    """
    return False


# Miscellaneous API
def value_return(value):
    """
    Mock function for near_value_return.
    :param value: Value to return.
    """
    pass


def panic():
    """
    Mock function for near_panic.
    """
    pass


def panic_utf8(msg):
    """
    Mock function for near_panic_utf8.
    :param msg: Panic message.
    """
    pass


def log_utf8(msg):
    """
    Mock function for near_log_utf8.
    :param msg: Log message.
    """
    pass


def log(msg):
    """
    Alias for log_utf8()
    """
    pass


def log_utf16(msg):
    """
    Mock function for near_log_utf16.
    :param msg: Log message.
    """
    pass


def abort(msg, filename, line, col):
    """
    Mock function for near_abort.
    :param msg: Abort message.
    :param filename: Filename.
    :param line: Line number.
    :param col: Column number.
    """
    pass


# Promises API
def promise_create(account_id, function_name, arguments, amount, gas):
    """
    Mock function for near_promise_create.
    :param account_id: Account ID.
    :param function_name: Function name.
    :param arguments: Arguments.
    :param amount: Amount.
    :param gas: Gas.
    :return: Placeholder integer.
    """
    return 0


def promise_then(promise_index, account_id, function_name, arguments, amount, gas):
    """
    Mock function for near_promise_then.
    :param promise_index: Promise index.
    :param account_id: Account ID.
    :param function_name: Function name.
    :param arguments: Arguments.
    :param amount: Amount.
    :param gas: Gas.
    :return: Placeholder integer.
    """
    return 0


def promise_and(promise_indices):
    """
    Mock function for near_promise_and.
    :param promise_indices: List of promise indices.
    :return: Placeholder integer.
    """
    return 0


def promise_batch_create(account_id):
    """
    Mock function for near_promise_batch_create.
    :param account_id: Account ID.
    :return: Placeholder integer.
    """
    return 0


def promise_batch_then(promise_index, account_id):
    """
    Mock function for near_promise_batch_then.
    :param promise_index: Promise index.
    :param account_id: Account ID.
    :return: Placeholder integer.
    """
    return 0


def promise_batch_action_create_account(promise_index):
    """
    Mock function for near_promise_batch_action_create_account.
    :param promise_index: Promise index.
    """
    pass


def promise_batch_action_deploy_contract(promise_index, code):
    """
    Mock function for near_promise_batch_action_deploy_contract.
    :param promise_index: Promise index.
    :param code: Contract code.
    """
    pass


def promise_batch_action_function_call(promise_index, function_name, arguments, amount, gas):
    """
    Mock function for near_promise_batch_action_function_call.
    :param promise_index: Promise index.
    :param function_name: Function name.
    :param arguments: Arguments.
    :param amount: Amount.
    :param gas: Gas.
    """
    pass


def promise_batch_action_function_call_weight(promise_index, function_name, arguments, amount, gas, weight):
    """
    Mock function for near_promise_batch_action_function_call_weight.
    :param promise_index: Promise index.
    :param function_name: Function name.
    :param arguments: Arguments.
    :param amount: Amount.
    :param gas: Gas.
    :param weight: Weight.
    """
    pass


def promise_batch_action_transfer(promise_index, amount):
    """
    Mock function for near_promise_batch_action_transfer.
    :param promise_index: Promise index.
    :param amount: Amount.
    """
    pass


def promise_batch_action_stake(promise_index, amount, pub_key):
    """
    Mock function for near_promise_batch_action_stake.
    :param promise_index: Promise index.
    :param amount: Amount.
    :param pub_key: Public key.
    """
    pass


def promise_batch_action_add_key_with_full_access(promise_index, public_key, nonce):
    """
    Mock function for near_promise_batch_action_add_key_with_full_access.
    :param promise_index: Promise index.
    :param public_key: Public key.
    :param nonce: Nonce.
    """
    pass


def promise_batch_action_add_key_with_function_call(
    promise_index, public_key, nonce, allowance, receiver_id, function_names
):
    """
    Mock function for near_promise_batch_action_add_key_with_function_call.
    :param promise_index: Promise index.
    :param public_key: Public key.
    :param nonce: Nonce.
    :param allowance: Allowance.
    :param receiver_id: Receiver ID.
    :param function_names: Function names.
    """
    pass


def promise_batch_action_delete_key(promise_index, public_key):
    """
    Mock function for near_promise_batch_action_delete_key.
    :param promise_index: Promise index.
    :param public_key: Public key.
    """
    pass


def promise_batch_action_delete_account(promise_index, beneficiary_id):
    """
    Mock function for near_promise_batch_action_delete_account.
    :param promise_index: Promise index.
    :param beneficiary_id: Beneficiary ID.
    """
    pass


def promise_yield_create(function_name, arguments, gas, gas_weight):
    """
    Mock function for near_promise_yield_create.
    :param function_name: Function name.
    :param arguments: Arguments.
    :param gas: Gas.
    :param gas_weight: Gas weight.
    :return: Placeholder tuple.
    """
    return (0, "")


def promise_yield_resume(data_id, payload):
    """
    Mock function for near_promise_yield_resume.
    :param data_id: Data ID.
    :param payload: Payload.
    :return: Placeholder boolean.
    """
    return False


def promise_results_count():
    """
    Mock function for near_promise_results_count.
    :return: Placeholder integer.
    """
    return 0


def promise_result(result_idx):
    """
    Mock function for near_promise_result.
    :param result_idx: Result index.
    :return: Placeholder tuple.
    """
    return (0, b"")


def promise_result_as_str(result_idx):
    """
    Mock function for near_promise_result_as_str.
    :param result_idx: Result index.
    :return: Placeholder tuple.
    """
    return (0, "")


def promise_return(promise_id):
    """
    Mock function for near_promise_return.
    :param promise_id: Promise ID.
    """
    pass


# Storage API
def storage_write(key, value):
    """
    Mock function for near_storage_write.
    :param key: Key.
    :param value: Value.
    :return: Placeholder tuple.
    """
    return b""


def storage_read(key):
    """
    Mock function for near_storage_read.
    :param key: Key.
    :return: Placeholder tuple.
    """
    return b""


def storage_remove(key):
    """
    Mock function for near_storage_remove.
    :param key: Key.
    :return: Placeholder tuple.
    """
    return b""


def storage_has_key(key):
    """
    Mock function for near_storage_has_key.
    :param key: Key.
    :return: Placeholder integer.
    """
    return False


# Validator API
def validator_stake(account_id):
    """
    Mock function for near_validator_stake.
    :param account_id: Account ID.
    :return: Placeholder integer.
    """
    return 0


def validator_total_stake():
    """
    Mock function for near_validator_total_stake.
    :return: Placeholder integer.
    """
    return 0


# Alt BN128 API
def alt_bn128_g1_multiexp(value):
    """
    Mock function for near_alt_bn128_g1_multiexp.
    :param value: Input value.
    :return: Placeholder bytes.
    """
    return b""


def alt_bn128_g1_sum(value):
    """
    Mock function for near_alt_bn128_g1_sum.
    :param value: Input value.
    :return: Placeholder bytes.
    """
    return b""


def alt_bn128_pairing_check(value):
    """
    Mock function for near_alt_bn128_pairing_check.
    :param value: Input value.
    :return: Placeholder boolean.
    """
    return False
