import json

import near

"""Experimental port of https://github.com/near/near-sdk-rs/tree/master/near-contract-standards/src/fungible_token contract"""


def from_tgas(tgas):
    return tgas * 1000000000000


FT_METADATA_SPEC = "ft-1.0.0"
DATA_IMAGE_SVG_NEAR_ICON = "data:image/svg+xml,%3Csvg xmlns='http:#www.w3.org/2000/svg' viewBox='0 0 288 288'%3E%3Cg id='l' data-name='l'%3E%3Cpath d='M187.58,79.81l-30.1,44.69a3.2,3.2,0,0,0,4.75,4.2L191.86,103a1.2,1.2,0,0,1,2,.91v80.46a1.2,1.2,0,0,1-2.12.77L102.18,77.93A15.35,15.35,0,0,0,90.47,72.5H87.34A15.34,15.34,0,0,0,72,87.84V201.16A15.34,15.34,0,0,0,87.34,216.5h0a15.35,15.35,0,0,0,13.08-7.31l30.1-44.69a3.2,3.2,0,0,0-4.75-4.2L96.14,186a1.2,1.2,0,0,1-2-.91V104.61a1.2,1.2,0,0,1,2.12-.77l89.55,107.23a15.35,15.35,0,0,0,11.71,5.43h3.13A15.34,15.34,0,0,0,216,201.16V87.84A15.34,15.34,0,0,0,200.66,72.5h0A15.35,15.35,0,0,0,187.58,79.81Z'/%3E%3C/g%3E%3C/svg%3E"

GAS_FOR_RESOLVE_TRANSFER = from_tgas(5)
GAS_FOR_FT_TRANSFER_CALL = from_tgas(30)

STATE_STORAGE_KEY = "STATE"


def storage_byte_cost():
    return 10000000000000000000


def saturating_mul(x, y):
    return min(max(x * y, 0), 2**128)


def saturating_add(x, y):
    return min(max(x + y, 0), 2**128)


def saturating_sub(x, y):
    return min(max(x - y, 0), 2**128)


def checked_add(x, y):
    result = x + y
    assert result >= 0 and result < 2**128
    return result


def checked_sub(x, y):
    result = x - y
    assert result >= 0 and result < 2**128
    return result


def read_str(key):
    """Reads a string value from storage, returns None if none found"""
    value = near.storage_read(key)
    return value.decode("utf-8") if value is not None else None


def write_str(key, value):
    """Writes a string value into storage, returns previous value which was overwritten or None"""
    prev_value = near.storage_write(key, value.encode("uft-8"))
    return prev_value.decode("utf-8") if prev_value is not None else None


def get_account_balance(account_id):
    balance_str = read_str(f"{STATE_STORAGE_KEY}.accounts.{account_id}")
    return int(balance_str) if balance_str else None


def set_account_balance(account_id, balance):
    near.log_utf8(f"set_account_balance({account_id}, {balance})")
    assert balance >= 0
    zero_pad = "0" * (39 - len(str(balance)))
    prev_balance_str = write_str(
        f"{STATE_STORAGE_KEY}.accounts.{account_id}", zero_pad + str(balance)
    )  # this ensures all account balances consume the same amount of storage
    return int(prev_balance_str) if prev_balance_str else None


def remove_account(account_id):
    near.storage_remove(f"{STATE_STORAGE_KEY}.accounts.{account_id}")


def emit_event(event, data):
    near.log_utf8("EVENT_JSON:" + json.dumps({"standard": "nep141", "version": "1.0.0", "event": event, "data": data}))


def near_wrap(fn):
    def wrapped_fn():
        state_str = read_str(STATE_STORAGE_KEY)
        state = json.loads(state_str) if state_str is not None else {}
        near.log_utf8(f"near_wrap({fn.__name__}): state before function call: {state}")
        args = json.loads(near.input().decode("utf-8"))
        near.log_utf8(f"near_wrap({fn.__name__}): args {args}")
        args["state"] = state
        return_value = fn(**args)
        near.log_utf8(f"near_wrap({fn.__name__}): state after function call {state}")
        write_str(STATE_STORAGE_KEY, json.dumps(state))
        if return_value is not None:
            near.log_utf8(f"near_wrap({fn.__name__}): returning value {return_value}")
            near.value_return(return_value)

    return wrapped_fn


def validate_metadata(metadata):
    assert metadata["spec"] == FT_METADATA_SPEC
    assert isinstance(metadata["name"], str) and len(metadata["name"]) > 0
    assert isinstance(metadata["symbol"], str) and len(metadata["symbol"]) > 0
    assert metadata["decimals"] == 24
    return metadata


def measure_account_storage_usage():
    initial_storage_usage = near.storage_usage()
    tmp_account_id = "a" * 64
    set_account_balance(tmp_account_id, 0)
    account_storage_usage = near.storage_usage() - initial_storage_usage
    remove_account(tmp_account_id)
    near.log_utf8(f"measure_account_storage_usage(): {account_storage_usage}")
    return account_storage_usage


def internal_new(state, owner_id, total_supply, metadata_json):
    near.log_utf8(f"internal_new({state}, {owner_id}, {total_supply}, {metadata_json}")
    if near.storage_has_key(STATE_STORAGE_KEY):
        near.panic_utf8("Already initialized")
    state["total_supply"] = "0"
    state["account_storage_usage"] = str(measure_account_storage_usage())
    internal_register_account(owner_id)
    internal_deposit(state, owner_id, total_supply)
    near.log_utf8(f"internal_new(): writing metadata")
    write_str("metadata", json.dumps(validate_metadata(json.loads(metadata_json))))
    near.log_utf8(f"internal_new(): emitting event")
    emit_event(
        "ft_mint",
        {
            "owner_id": owner_id,
            "amount": str(total_supply),
            "memo": "new tokens are minted",
        },
    )
    near.log_utf8(f"internal_new(): done")


@near.export
@near_wrap
def new(state, owner_id, total_supply, metadata_json):
    """
    Initializes the contract with the given total supply owned by the given `owner_id` with
    the given fungible token metadata.
    """
    internal_new(state, owner_id, int(total_supply), metadata_json)


@near_wrap
@near.export
def new_default_meta(state, owner_id, total_supply):
    internal_new(
        state,
        owner_id,
        int(total_supply),
        json.dumps(
            {
                "spec": FT_METADATA_SPEC,
                "name": "Example NEAR fungible token",
                "symbol": "EXAMPLE",
                "icon": DATA_IMAGE_SVG_NEAR_ICON,
                "reference": None,
                "reference_hash": None,
                "decimals": 24,
            }
        ),
    )


def assert_one_yocto():
    """Requires attached deposit of exactly 1 yoctoNEAR"""
    assert near.attached_deposit() == 1


def internal_unwrap_balance_of(account_id):
    balance = get_account_balance(account_id)
    if balance is None:
        near.panic_utf8(f"The account {account_id} is not registered")
    return balance


def internal_deposit(state, account_id, amount):
    near.log_utf8(f"internal_deposit({account_id}, {amount})")
    set_account_balance(account_id, checked_add(internal_unwrap_balance_of(account_id), amount))
    state["total_supply"] = str(checked_add(int(state["total_supply"]), amount))


def internal_withdraw(state, account_id, amount):
    near.log_utf8(f"internal_withdraw({account_id}, {amount})")
    set_account_balance(account_id, checked_sub(internal_unwrap_balance_of(account_id), amount))
    state["total_supply"] = str(checked_sub(int(state["total_supply"]), amount))


def internal_transfer(state, sender_id, receiver_id, amount, memo):
    near.log_utf8(f"internal_transfer({sender_id}, {receiver_id}, {amount}, {memo})")
    assert sender_id != receiver_id, "Sender and receiver should be different"
    assert amount > 0, "The amount should be a positive number"
    internal_withdraw(state, sender_id, amount)
    internal_deposit(state, receiver_id, amount)
    emit_event(
        "ft_mint",
        {
            "old_owner_id": sender_id,
            "new_owner_id": receiver_id,
            "amount": amount,
            "memo": memo,
        },
    )


@near.export
@near_wrap
def ft_transfer(state, receiver_id, amount, memo):
    assert_one_yocto()
    amount = int(amount)
    sender_id = near.predecessor_account_id()
    internal_transfer(state, sender_id, receiver_id, amount, memo)


@near.export
@near_wrap
def ft_transfer_call(state, receiver_id, amount, memo, msg=""):
    assert_one_yocto()
    assert near.prepaid_gas() > GAS_FOR_FT_TRANSFER_CALL
    amount = int(amount)
    sender_id = near.predecessor_account_id()
    near.log_utf8(f"ft_transfer_call({receiver_id}, {amount}, {memo}, {msg}): sender_id {sender_id}")
    internal_transfer(state, sender_id, receiver_id, amount, memo)
    receiver_gas = checked_sub(near.prepaid_gas(), GAS_FOR_FT_TRANSFER_CALL)
    # Initiating receiver's call and the callback
    near.log_utf8(f"ft_transfer_call(): calling promise_create with receiver_gas {receiver_gas}")
    promise_index = near.promise_create(
        receiver_id,
        "ft_on_transfer",
        json.dumps({"sender_id": sender_id, "amount": amount, "msg": msg}),
        int(amount),
        receiver_gas,
    )
    return str(
        near.promise_then(
            promise_index,
            near.current_account_id(),
            "ft_resolve_transfer",
            json.dumps({"sender_id": sender_id, "receiver_id": receiver_id, "amount": amount}),
            int(amount),
            GAS_FOR_RESOLVE_TRANSFER,
        )
    )


@near.export
@near_wrap
def ft_total_supply(state):
    return state["total_supply"]


@near.export
@near_wrap
def ft_balance_of(state, account_id):
    return str(get_account_balance(account_id))


def internal_ft_resolve_transfer(state, sender_id, receiver_id, amount):
    # Get the unused amount from the `ft_on_transfer` call result.
    amount = int(amount)
    result, unused_amount = near.promise_result(0)
    unused_amount = min(amount, unused_amount) if result == 1 else amount
    if unused_amount > 0:
        receiver_balance = get_account_balance(receiver_id)
        if receiver_balance > 0:
            refund_amount = min(receiver_balance, unused_amount)
            set_account_balance(receiver_id, checked_sub(receiver_balance, refund_amount))
            sender_balance = get_account_balance(sender_id)
            if sender_balance is not None:
                set_account_balance(sender_id, checked_add(sender_balance, refund_amount))
                emit_event(
                    "ft_transfer",
                    {
                        "old_owner_id": receiver_id,
                        "new_owner_id": sender_id,
                        "amount": str(refund_amount),
                        "memo": "refund",
                    },
                )
                used_amount = checked_sub(amount, refund_amount)
                return used_amount, 0
            else:
                # Sender's account was deleted, so we need to burn tokens.
                total_supply = checked_sub(total_supply, refund_amount)
                near.log_utf8("The account of the sender was deleted")
                emit_event(
                    "ft_burn",
                    {
                        "owner_id": receiver_id,
                        "amount": str(refund_amount),
                        "memo": "refund",
                    },
                )
                return amount, refund_amount
    return amount, 0


@near.export
@near_wrap
def ft_resolve_transfer(state, sender_id, receiver_id, amount):
    near.log_utf8(f"ft_resolve_transfer({sender_id}, {receiver_id}, {amount})")
    used_amount, burned_amount = internal_ft_resolve_transfer(state, sender_id, receiver_id, amount)
    if burned_amount > 0:
        near.log(f"Account @{sender_id} burned {burned_amount}")
    return str(used_amount)


def internal_register_account(account_id):
    near.log_utf8(f"internal_register_account({account_id})")
    if set_account_balance(account_id, 0) is not None:
        near.panic_utf8("The account is already registered")


def internal_storage_unregister(state, force):
    assert_one_yocto()
    account_id = near.predecessor_account_id()
    balance = get_account_balance(account_id)
    if balance is not None:
        if balance == 0 or force:
            remove_account(account_id)
            state["total_supply"] -= balance
            near.promise_batch_action_transfer(
                near.promise_batch_create(account_id), saturating_add(internal_storage_balance_bounds()["min"], 1)
            )
            return account_id, balance
        else:
            near.panic_utf8("Can't unregister the account with the positive balance without force")
    else:
        near.log_utf8(f"The account {account_id} is not registered")
    return None


def internal_storage_balance_of(state, account_id):
    balance = get_account_balance(account_id)
    return (
        json.dumps(
            {
                "total": internal_storage_balance_bounds(state)["min"],
                "available": "0",
            }
        )
        if balance is not None
        else None
    )


@near.export
@near_wrap
def storage_deposit(state, account_id, registration_only=False):
    amount = near.attached_deposit()
    account_id = account_id if account_id else near.predecessor_account_id()
    if get_account_balance(account_id) is not None:
        near.log_utf8("The account is already registered, refunding the deposit")
        if amount > 0:
            near.promise_batch_action_transfer(near.promise_batch_create(near.predecessor_account_id()), amount)
    else:
        min_balance = internal_storage_balance_bounds(state)["min"]
        if amount < min_balance:
            near.panic_utf8("The attached deposit is less than the minimum storage balance")
        internal_register_account(account_id)
        refund = saturating_sub(amount, min_balance)
        if refund > 0:
            near.promise_batch_action_transfer(near.promise_batch_create(near.predecessor_account_id()), refund)
    return internal_storage_balance_of(state, account_id)


@near.export
@near_wrap
def storage_withdraw(state, amount):
    assert_one_yocto()
    predecessor_account_id = near.predecessor_account_id()
    storage_balance = internal_storage_balance_of(state, predecessor_account_id)
    if storage_balance is None:
        near.panic_utf8(f"The account {predecessor_account_id} is not registered")
    if amount > 0:
        near.panic_utf8("The amount is greater than the available storage balance")
    return storage_balance


@near.export
@near_wrap
def storage_unregister(state, force):
    account_id, balance = internal_storage_unregister(state, force)
    if account_id is not None:
        near.log_utf8(f"Closed @{account_id} with: {balance}")
        return True
    return False


def internal_storage_balance_bounds(state):
    required_storage_balance = saturating_mul(storage_byte_cost(), int(state["account_storage_usage"]))
    return {"min": required_storage_balance, "max": required_storage_balance}


@near.export
@near_wrap
def storage_balance_bounds(state):
    return json.dumps(internal_storage_balance_bounds(state))


@near.export
@near_wrap
def storage_balance_of(state, account_id):
    return internal_storage_balance_of(state, account_id)


@near.export
@near_wrap
def ft_metadata():
    return read_str("metadata")


def test_new():
    metadata = json.dumps(
        {
            "spec": FT_METADATA_SPEC,
            "name": "Example NEAR fungible token",
            "symbol": "EXAMPLE",
            "icon": DATA_IMAGE_SVG_NEAR_ICON,
            "reference": None,
            "reference_hash": None,
            "decimals": 24,
        }
    )
    near.test_create_account()
    contract_owner_account_id = near.test_account_id()
    result, gas_burnt = near.test_method(
        __file__,
        "new",
        json.dumps(
            {"owner_id": contract_owner_account_id, "total_supply": str(1000000000000000), "metadata_json": metadata}
        ),
    )
    assert result == b""
    receiver_account_id = f"{id(object())}.{contract_owner_account_id}"
    result, gas_burnt = near.test_method(
        __file__,
        "storage_deposit",
        json.dumps({"account_id": receiver_account_id}),
        attached_deposit="1600000000000000000000 yNEAR",
        skip_deploy=True,
    )
    assert result == b'{"available": "0", "total": 1580000000000000000000}'
    result, gas_burnt = near.test_method(
        __file__,
        "ft_transfer",
        json.dumps({"receiver_id": receiver_account_id, "amount": "1000", "memo": ""}),
        attached_deposit="1 yNEAR",
        skip_deploy=True,
    )
    assert result == b""
    result, gas_burnt = near.test_method(
        __file__, "ft_balance_of", json.dumps({"account_id": receiver_account_id}), skip_deploy=True
    )
    assert result == b"1000"
    result, gas_burnt = near.test_method(
        __file__,
        "ft_transfer_call",
        json.dumps({"receiver_id": receiver_account_id, "amount": "1000", "memo": ""}),
        attached_deposit="1 yNEAR",
        skip_deploy=True,
    )
    assert result == b"1"
    result, gas_burnt = near.test_method(
        __file__, "ft_balance_of", json.dumps({"account_id": receiver_account_id}), skip_deploy=True
    )
    assert result == b"1000"
    result, gas_burnt = near.test_method(
        __file__, "ft_balance_of", json.dumps({"account_id": contract_owner_account_id}), skip_deploy=True
    )
    assert result == b"999999999999000"
    result, gas_burnt = near.test_method(__file__, "ft_total_supply", "{}", skip_deploy=True)
    assert result == b"1000000000000000"
