import base64
import json

import near

"""Experimental port of https:#github.com/near/near-sdk-rs/tree/master/near-contract-standards/src/non_fungible_token contract"""


def from_tgas(tgas):
    return tgas * 1000000000000


NFT_METADATA_SPEC = "nft-1.0.0"
DATA_IMAGE_SVG_NEAR_ICON = "data:image/svg+xml,%3Csvg xmlns='http:#www.w3.org/2000/svg' viewBox='0 0 288 288'%3E%3Cg id='l' data-name='l'%3E%3Cpath d='M187.58,79.81l-30.1,44.69a3.2,3.2,0,0,0,4.75,4.2L191.86,103a1.2,1.2,0,0,1,2,.91v80.46a1.2,1.2,0,0,1-2.12.77L102.18,77.93A15.35,15.35,0,0,0,90.47,72.5H87.34A15.34,15.34,0,0,0,72,87.84V201.16A15.34,15.34,0,0,0,87.34,216.5h0a15.35,15.35,0,0,0,13.08-7.31l30.1-44.69a3.2,3.2,0,0,0-4.75-4.2L96.14,186a1.2,1.2,0,0,1-2-.91V104.61a1.2,1.2,0,0,1,2.12-.77l89.55,107.23a15.35,15.35,0,0,0,11.71,5.43h3.13A15.34,15.34,0,0,0,216,201.16V87.84A15.34,15.34,0,0,0,200.66,72.5h0A15.35,15.35,0,0,0,187.58,79.81Z'/%3E%3C/g%3E%3C/svg%3E"

GAS_FOR_RESOLVE_TRANSFER = from_tgas(5)
GAS_FOR_NFT_TRANSFER_CALL = from_tgas(30)
GAS_FOR_NFT_APPROVE = from_tgas(10)

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


def emit_event(event, data):
    near.log_utf8("EVENT_JSON:" + json.dumps({"standard": "nep171", "version": "1.0.0", "event": event, "data": data}))


def emit_transfer(owner_id, receiver_id, token_id, sender_id, memo):
    emit_event(
        "transfer",
        {
            "old_owner_id": owner_id,
            "new_owner_id": receiver_id,
            "token_ids": [token_id],
            "authorized_id": [sender_id] if sender_id and sender_id != owner_id else [],
            "memo": memo,
        },
    )


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
    assert metadata["spec"] == NFT_METADATA_SPEC
    assert isinstance(metadata["name"], str) and len(metadata["name"]) > 0
    assert isinstance(metadata["symbol"], str) and len(metadata["symbol"]) > 0
    return metadata


def bytes_for_approved_account_id(account_id):
    return len(json.dumps({account_id: 2 ^ 53 - 1}))


def refund_approved_account_ids_iter(account_id, approved_account_ids):
    storage_released = sum([bytes_for_approved_account_id(account_id) for account_id in approved_account_ids])
    near.promise_batch_action_transfer(
        near.promise_batch_create(account_id), saturating_mul(storage_byte_cost(), storage_released)
    )


def refund_approved_account_ids(account_id, approved_account_ids):
    refund_approved_account_ids_iter(account_id, approved_account_ids.keys())


def refund_deposit_to_account(storage_used, account_id):
    required_cost = saturating_mul(storage_byte_cost(), storage_used)
    attached_deposit = near.attached_deposit()
    assert required_cost <= attached_deposit, f"Must attach {required_cost} to cover storage"
    refund = saturating_sub(attached_deposit, required_cost)
    if refund > 1:
        near.promise_batch_action_transfer(near.promise_batch_create(account_id), refund)


# Assumes that the precedecessor will be refunded
def refund_deposit(storage_used):
    refund_deposit_to_account(storage_used, near.predecessor_account_id())


def measure_min_token_storage_cost(state):
    tmp_token_id = "a" * 64
    tmp_owner_id = "a" * 64
    state_copy = {
        "owner_by_id": {},
        "token_metadata_by_id": {},
        "tokens_per_owner": {},
        "approvals_by_id": {},
        "next_approval_id_by_id": {},
    }
    write_str(STATE_STORAGE_KEY + "_temp", json.dumps(state_copy))
    initial_storage_usage = near.storage_usage()
    state_copy["owner_by_id"][tmp_token_id] = tmp_owner_id
    if "token_metadata_by_id" in state:
        state_copy["token_metadata_by_id"][tmp_token_id] = {
            "title": "a" * 64,
            "description": "a" * 64,
            "media": "a" * 64,
            "media_hash": "YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYQ==",
            # "media_hash": base64.b64encode(("a" * 64).encode("utf-8")),
            "copies": 1,
            "issued_at": None,
            "expires_at": None,
            "starts_at": None,
            "updated_at": None,
            "extra": None,
            "reference": None,
            "reference_hash": None,
        }
    if "tokens_per_owner" in state:
        state_copy["tokens_per_owner"][tmp_owner_id] = {}
    if "approvals_by_id" in state:
        state_copy["approvals_by_id"][tmp_token_id] = {tmp_owner_id: 1}
        state_copy["next_approval_id_by_id"][tmp_token_id] = 1
    write_str(STATE_STORAGE_KEY + "_temp", json.dumps(state_copy))
    account_storage_usage = near.storage_usage() - initial_storage_usage
    near.storage_remove(STATE_STORAGE_KEY + "_temp")
    near.log_utf8(f"measure_min_token_storage_cost(): {account_storage_usage}")
    return account_storage_usage


# Transfer token_id from `from` to `to`
#
# Do not perform any safety checks or do any logging
def internal_transfer_unguarded(state, token_id, from_, to):
    # update owner
    state["owner_by_id"][token_id] = to
    # if using Enumeration standard, update old & new owner's token lists
    if "tokens_per_owner" in state:
        state["tokens_per_owner"].get(from_, {}).pop(token_id, None)
        if to not in state["tokens_per_owner"]:
            state["tokens_per_owner"][to] = {}
        state["tokens_per_owner"][to][token_id] = True


# Transfer from current owner to receiver_id, checking that sender is allowed to transfer.
# Clear approvals, if approval extension being used.
# Return previous owner and approvals.
def internal_transfer(state, sender_id, receiver_id, token_id, approval_id, memo):
    near.log_utf8(f"internal_transfer({sender_id}, {receiver_id}, {token_id}, {approval_id}, {memo})")
    owner_id = state["owner_by_id"].get(token_id)
    assert owner_id, "Token not found"
    approved_account_ids = {}
    if "approvals_by_id" in state:
        approved_account_ids = state["approvals_by_id"][token_id].copy()
        # clear approvals, if using Approval Management extension
        # this will be rolled back by a panic if sending fails
        state["approvals_by_id"][token_id] = {}
        # check if authorized
        if sender_id != owner_id:
            assert sender_id in approved_account_ids, "Sender not approved"
            actual_approval_id = approved_account_ids.get(sender_id, None)
            assert (
                not approval_id or actual_approval_id == approval_id
            ), "The actual approval_id {actual_approval_id} is different from the given approval_id {approval_id}"
        else:
            sender_id = None
    assert owner_id != receiver_id, "Current and next owner must differ"
    internal_transfer_unguarded(state, token_id, owner_id, receiver_id)
    emit_transfer(owner_id, receiver_id, token_id, sender_id, memo)
    # return previous owner & approvals
    return owner_id, approved_account_ids.keys()


# Mint a new token without checking:
# * Whether the caller id is equal to the `owner_id`
# * Assumes there will be a refund to the predecessor after covering the storage costs
#
# Returns the newly minted token and emits the mint event
def internal_mint(state, token_id, token_owner_id, token_metadata):
    token = internal_mint_with_refund(state, token_id, token_owner_id, token_metadata, near.predecessor_account_id())
    emit_event(
        "nft_mint",
        {
            "owner_id": state["owner_id"],
            "token_ids": [token_id],
            "memo": None,
        },
    )
    return token


# Mint a new token without checking:
# * Whether the caller id is equal to the `owner_id`
# * `refund_id` will transfer the left over balance after storage costs are calculated to the provided account.
#   Typically the account will be the owner. If `None`, will not refund. This is useful for delaying refunding
#   until multiple tokens have been minted.
#
# Returns the newly minted token and does not emit the mint event. This allows minting multiple before emitting.
def internal_mint_with_refund(state, token_id, token_owner_id, token_metadata, refund_id):
    near.log_utf8(f"internal_mint_with_refund({token_id}, {token_owner_id}, {token_metadata}, {refund_id})")
    # Remember current storage usage if refund_id is Some
    initial_storage_usage = (refund_id, near.storage_usage()) if refund_id else (None, 0)
    assert "token_metadata_by_id" not in state or token_metadata, "Must provide metadata"
    if state["owner_by_id"].get(token_id):
        near.panic_utf8("token_id must be unique")
    owner_id = token_owner_id
    # Core behavior: every token must have an owner
    state["owner_by_id"][token_id] = owner_id
    # Metadata extension: Save metadata, keep variable around to return later.
    # Note that check above already panicked if metadata extension in use but no metadata
    # provided to call.
    if "token_metadata_by_id" in state:
        state["token_metadata_by_id"][token_id] = token_metadata
    # Enumeration extension: Record tokens_per_owner for use with enumeration view methods.
    if "tokens_per_owner" in state:
        if owner_id not in state["tokens_per_owner"]:
            state["tokens_per_owner"][owner_id] = {}
        state["tokens_per_owner"][owner_id][token_id] = True
    # Approval Management extension: return empty HashMap as part of Token
    approved_account_ids = {} if "approvals_by_id" in state else None
    if initial_storage_usage[0]:
        refund_deposit_to_account(near.storage_usage() - initial_storage_usage[1], initial_storage_usage[0])
    # Return any extra attached deposit not used for storage
    return {
        "token_id": token_id,
        "owner_id": owner_id,
        "metadata": token_metadata,
        "approved_account_ids": approved_account_ids,
    }


def assert_one_yocto():
    """Requires attached deposit of exactly 1 yoctoNEAR"""
    assert near.attached_deposit() == 1


def assert_at_least_one_yocto():
    """Requires attached deposit of at least 1 yoctoNEAR"""
    assert near.attached_deposit() >= 1


@near.export
@near_wrap
def nft_transfer(state, receiver_id, token_id, approval_id, memo):
    assert_one_yocto()
    sender_id = near.predecessor_account_id()
    internal_transfer(state, sender_id, receiver_id, token_id, approval_id, memo)


@near.export
@near_wrap
def nft_transfer_call(state, receiver_id, token_id, approval_id, memo, msg):
    assert_one_yocto()
    assert near.prepaid_gas() > GAS_FOR_NFT_TRANSFER_CALL, "More gas is required"
    sender_id = near.predecessor_account_id()
    (old_owner, old_approvals) = internal_transfer(state, sender_id, receiver_id, token_id, approval_id, memo)
    # Initiating receiver's call and the callback
    promise_index = near.promise_create(
        receiver_id,
        "nft_on_transfer",
        json.dumps({"sender_id": sender_id, "old_owner": old_owner, "token_id": token_id, "msg": msg}),
        0,
        saturating_sub(near.prepaid_gas(), GAS_FOR_NFT_TRANSFER_CALL),
    )
    return str(
        near.promise_then(
            promise_index,
            near.current_account_id(),
            "nft_resolve_transfer",
            json.dumps(
                {
                    "old_owner": old_owner,
                    "receiver_id": receiver_id,
                    "token_id": token_id,
                    "old_approvals": old_approvals,
                }
            ),
            0,
            GAS_FOR_RESOLVE_TRANSFER,
        )
    )


@near.export
@near_wrap
def nft_token(state, token_id):
    owner_id = state["owner_by_id"].get(token_id)
    assert owner_id, "Token not found"
    metadata = state["token_metadata_by_id"][token_id] if "token_metadata_by_id" in state else None
    approved_account_ids = state["approvals_by_id"].get(token_id, {}) if "approvals_by_id" in state else None
    return json.dumps(
        {
            "token_id": token_id,
            "owner_id": owner_id,
            "metadata": metadata,
            "approved_account_ids": approved_account_ids,
        }
    )


@near.export
@near_wrap
def nft_resolve_transfer(state, previous_owner_id, receiver_id, token_id, approved_account_ids):
    # Get whether token should be returned
    (result, value) = near.promise_result(0)
    must_revert = json.loads(value) if result == 1 else True
    # if call succeeded, return early
    if not must_revert:
        return json.dumps(True)
    # OTHERWISE, try to set owner back to previous_owner_id and restore approved_account_ids
    # Check that receiver didn't already transfer it away or burn it.
    current_owner = state["owner_by_id"].get(token_id)
    if current_owner:
        if current_owner != receiver_id:
            # The token is not owned by the receiver anymore. Can't return it.
            return json.dumps(True)
    else:
        # The token was burned and doesn't exist anymore.
        # Refund storage cost for storing approvals to original owner and return early.
        if approved_account_ids:
            refund_approved_account_ids(previous_owner_id, approved_account_ids)
        return json.dumps(True)
    internal_transfer_unguarded(state, token_id, receiver_id, previous_owner_id)
    # If using Approval Management extension,
    # 1. revert any approvals receiver already set, refunding storage costs
    # 2. reset approvals to what previous owner had set before call to nft_transfer_call
    approved_account_ids = state["approvals_by_id"].get(token_id, {}) if "approvals_by_id" in state else None
    if approved_account_ids:
        refund_approved_account_ids(receiver_id, approved_account_ids)
        state["approvals_by_id"][token_id] = {}
    emit_transfer(receiver_id, previous_owner_id, token_id, None, None)
    return json.dumps(False)


# Helper function used by a enumerations methods
# Note: this method is not exposed publicly to end users
def enum_get_token(state, owner_id, token_id):
    metadata = state["token_metadata_by_id"][token_id]
    approved_account_ids = state["approvals_by_id"].get(token_id, {}) if "approvals_by_id" in state else None
    return {
        "token_id": token_id,
        "owner_id": owner_id,
        "metadata": metadata,
        "approved_account_ids": approved_account_ids,
    }


@near.export
@near_wrap
def nft_total_supply(state):
    # An unfortunate cast from the max of TreeMap to the spec
    return str(len(state["owner_by_id"]))


@near.export
@near_wrap
def nft_tokens(state, from_index, limit):
    # Get starting index, whether or not it was explicitly given.
    # Defaults to 0 based on the spec:
    # https:#nomicon.io/Standards/NonFungibleToken/Enumeration.html#interface
    start_index = from_index if from_index else 0
    assert len(state["owner_by_id"]) >= start_index, "Out of bounds, please use a smaller from_index."
    limit = limit if limit else 2**64 - 1
    assert limit != 0, "Cannot provide limit of 0."
    tokens = []
    for token_id in state["owner_by_id"].keys()[start_index : start_index + limit]:
        tokens.append(enum_get_token(state, state["owner_by_id"]["owner_id"], token_id))
    return json.dumps(tokens)


@near.export
@near_wrap
def nft_supply_for_owner(state, account_id):
    assert (
        "tokens_per_owner" in state
    ), "Could not find tokens_per_owner when calling a method on the enumeration standard."
    return str(len(state["tokens_per_owner"].get(account_id, {})))


@near.export
@near_wrap
def nft_tokens_for_owner(state, account_id, from_index, limit):
    assert (
        "tokens_per_owner" in state
    ), "Could not find tokens_per_owner when calling a method on the enumeration standard."
    token_set = state["tokens_per_owner"].get(account_id, {})
    start_index = from_index if from_index else 0
    assert len(state["owner_by_id"]) >= start_index, "Out of bounds, please use a smaller from_index."
    limit = limit if limit else 2**64 - 1
    assert limit != 0, "Cannot provide limit of 0."
    tokens = []
    for token_id in token_set.keys()[start_index : start_index + limit]:
        tokens.append(enum_get_token(state, account_id, token_id))
    return json.dumps(tokens)


@near.export
@near_wrap
def nft_approve(state, token_id, account_id, msg):
    assert_at_least_one_yocto()
    assert "approvals_by_id" in state, "NFT does not support Approval Management"
    approvals_by_id = state["approvals_by_id"]

    owner_id = state["owner_by_id"].get(token_id)
    assert owner_id, "Token not found"

    assert near.predecessor_account_id() == owner_id, "Predecessor must be token owner."

    next_approval_id_by_id = state.get("next_approval_id_by_id")
    assert next_approval_id_by_id is not None, "next_approval_by_id must be set for approval ext"

    # update HashMap of approvals for this token
    approved_account_ids = approvals_by_id.get(token_id, {})
    approval_id = next_approval_id_by_id.get(token_id, 1)
    old_approval_id = approved_account_ids.get(account_id)
    approved_account_ids[account_id] = approval_id

    # save updated approvals HashMap to contract's LookupMap
    approvals_by_id[token_id] = approved_account_ids

    # increment next_approval_id for this token
    next_approval_id_by_id[token_id] = approval_id + 1

    # If this approval replaced existing for same account, no storage was used.
    # Otherwise, require that enough deposit was attached to pay for storage, and refund
    # excess.
    storage_used = bytes_for_approved_account_id(account_id) if old_approval_id is None else 0
    refund_deposit(storage_used)

    # if given `msg`, schedule call to `nft_on_approve` and return it. Else, return None.
    if msg:
        return str(
            near.promise_create(
                account_id,
                "nft_on_approve",
                json.dumps({"token_id": token_id, "owner_id": owner_id, "approval_id": approval_id, "msg": msg}),
                0,
                saturating_sub(near.prepaid_gas(), GAS_FOR_NFT_APPROVE),
            )
        )


@near.export
@near_wrap
def nft_revoke(state, token_id, account_id):
    assert_one_yocto()
    assert "approvals_by_id" in state, "NFT does not support Approval Management"
    approvals_by_id = state["approvals_by_id"]

    owner_id = state["owner_by_id"].get(token_id)
    assert owner_id, "Token not found"

    predecessor_account_id = near.predecessor_account_id()
    assert predecessor_account_id == owner_id, "Predecessor must be token owner."

    # if token has no approvals, do nothing
    approved_account_ids = approvals_by_id.get(token_id)
    if approved_account_ids:
        # if account_id was already not approved, do nothing
        if account_id in approved_account_ids:
            approved_account_ids.pop(account_id, None)
            refund_approved_account_ids_iter(predecessor_account_id, [account_id])
            # if this was the last approval, remove the whole HashMap to save space.
            if len(approved_account_ids) == 0:
                approvals_by_id.pop(token_id, None)
            else:
                # otherwise, update approvals_by_id with updated HashMap
                approvals_by_id[token_id] = approved_account_ids


@near.export
@near_wrap
def nft_revoke_all(state, token_id):
    assert_one_yocto()
    assert "approvals_by_id" in state, "NFT does not support Approval Management"
    approvals_by_id = state["approvals_by_id"]

    owner_id = state["owner_by_id"].get(token_id)
    assert owner_id, "Token not found"

    predecessor_account_id = near.predecessor_account_id()
    assert predecessor_account_id == owner_id, "Predecessor must be token owner."

    # if token has no approvals, do nothing
    approved_account_ids = approvals_by_id.get(token_id)
    if approved_account_ids:
        # otherwise, refund owner for storage costs of all approvals...
        refund_approved_account_ids(predecessor_account_id, approved_account_ids)
        # ...and remove whole HashMap of approvals
        approvals_by_id.pop(token_id, None)


@near.export
@near_wrap
def nft_is_approved(state, token_id, approved_account_id, approval_id=None):
    owner_id = state["owner_by_id"].get(token_id)
    assert owner_id, "Token not found"

    if "approvals_by_id" not in state:
        return json.dumps(False)

    approvals_by_id = state["approvals_by_id"]

    approved_account_ids = approvals_by_id.get(token_id)
    if not approved_account_ids:
        # token has no approvals
        return json.dumps(False)

    actual_approval_id = approved_account_ids.get(approved_account_id)
    if not actual_approval_id:
        # account not in approvals HashMap
        return json.dumps(False)

    if approval_id:
        return json.dumps(approval_id == actual_approval_id)
    else:
        # account approved, no approval_id given
        return json.dumps(True)


def internal_new(
    state, owner_id, metadata_json=None, enable_token_metadata=False, enable_enumeration=False, enable_approval=False
):
    near.log_utf8(f"internal_new({state}, {owner_id}, {metadata_json}")
    if near.storage_has_key(STATE_STORAGE_KEY):
        near.panic_utf8("Already initialized")
    state["owner_id"] = owner_id
    state["owner_by_id"] = {}
    if enable_token_metadata:
        state["token_metadata_by_id"] = {}
    if enable_enumeration:
        state["tokens_per_owner"] = {}
    if enable_approval:
        state["approvals_by_id"] = {}
        state["next_approval_id_by_id"] = {}
    state["extra_storage_in_bytes_per_token"] = str(measure_min_token_storage_cost(state))
    if metadata_json:
        near.log_utf8(f"internal_new(): writing metadata")
        write_str("metadata", json.dumps(validate_metadata(json.loads(metadata_json))))
    near.log_utf8(f"internal_new(): done")


@near.export
@near_wrap
def new(state, owner_id, metadata_json):
    """
    Initializes the contract with the given total supply owned by the given `owner_id` with
    the given fungible token metadata.
    """
    internal_new(
        state, owner_id, metadata_json, enable_token_metadata=True, enable_enumeration=True, enable_approval=True
    )


@near_wrap
@near.export
def new_default_meta(state, owner_id):
    internal_new(
        state,
        owner_id,
        json.dumps(
            {
                "spec": NFT_METADATA_SPEC,
                "name": "Example NEAR non-fungible token",
                "symbol": "EXAMPLE",
                "icon": DATA_IMAGE_SVG_NEAR_ICON,
                "base_uri": None,
                "reference": None,
                "reference_hash": None,
            }
        ),
    )


@near.export
@near_wrap
def nft_mint(state, token_id, token_owner_id, token_metadata):
    assert near.predecessor_account_id() == state["owner_id"]
    return json.dumps(internal_mint(state, token_id, token_owner_id, token_metadata))


@near.export
@near_wrap
def nft_transfer(state, receiver_id, token_id, approval_id, memo):
    assert_one_yocto()
    approval_id = int(approval_id) if approval_id else None
    sender_id = near.predecessor_account_id()
    internal_transfer(state, sender_id, receiver_id, token_id, approval_id, memo)


@near.export
@near_wrap
def nft_metadata():
    return read_str("metadata")


def test_new():
    metadata = json.dumps(
        {
            "spec": NFT_METADATA_SPEC,
            "name": "Example NEAR non-fungible token",
            "symbol": "EXAMPLE",
            "icon": DATA_IMAGE_SVG_NEAR_ICON,
            "base_uri": None,
            "reference": None,
            "reference_hash": None,
        }
    )
    near.test_create_account()
    contract_owner_account_id = near.test_account_id()
    result, gas_burnt = near.test_method(
        __file__,
        "new",
        json.dumps({"owner_id": contract_owner_account_id, "metadata_json": metadata}),
    )
    assert result == b""


def test_mint():
    contract_owner_account_id = near.test_account_id()
    token_metadata = {
        "title": "Olympus Mons",
        "description": "The tallest mountain in the charted solar system",
        "media": None,
        "media_hash": None,
        "copies": 1,
        "issued_at": None,
        "expires_at": None,
        "starts_at": None,
        "updated_at": None,
        "extra": None,
        "reference": None,
        "reference_hash": None,
    }
    result, gas_burnt = near.test_method(
        __file__,
        "nft_mint",
        json.dumps({"token_id": "0", "token_owner_id": contract_owner_account_id, "token_metadata": token_metadata}),
        attached_deposit="1 yNEAR",
        skip_deploy=True,
    )
    result_dict = json.loads(result)
    assert result_dict.get("token_id") == "0"
    assert result_dict.get("metadata") == token_metadata
    assert result_dict.get("owner_id") == contract_owner_account_id
    assert result_dict.get("approved_account_ids") == {}


def test_approve_revoke():
    contract_owner_account_id = near.test_account_id()
    approved_account_id = f"{id(object())}.{contract_owner_account_id}"
    result, gas_burnt = near.test_method(
        __file__,
        "nft_approve",
        json.dumps({"token_id": "0", "account_id": approved_account_id, "msg": None}),
        attached_deposit="900000000000000000000 yNEAR",
        skip_deploy=True,
    )
    assert result == b""
    result, gas_burnt = near.test_method(
        __file__,
        "nft_is_approved",
        json.dumps({"token_id": "0", "approved_account_id": approved_account_id}),
        attached_deposit="1 yNEAR",
        skip_deploy=True,
    )
    assert result == b"true"
    result, gas_burnt = near.test_method(
        __file__,
        "nft_revoke",
        json.dumps({"token_id": "0", "account_id": approved_account_id}),
        attached_deposit="1 yNEAR",
        skip_deploy=True,
    )
    assert result == b""
    result, gas_burnt = near.test_method(
        __file__,
        "nft_is_approved",
        json.dumps({"token_id": "0", "approved_account_id": approved_account_id}),
        attached_deposit="1 yNEAR",
        skip_deploy=True,
    )
    assert result == b"false"


def test_approve_revoke_all():
    contract_owner_account_id = near.test_account_id()
    approved_account_id = f"{id(object())}.{contract_owner_account_id}"
    result, gas_burnt = near.test_method(
        __file__,
        "nft_approve",
        json.dumps({"token_id": "0", "account_id": approved_account_id, "msg": None}),
        attached_deposit="900000000000000000000 yNEAR",
        skip_deploy=True,
    )
    assert result == b""
    result, gas_burnt = near.test_method(
        __file__,
        "nft_is_approved",
        json.dumps({"token_id": "0", "approved_account_id": approved_account_id}),
        attached_deposit="1 yNEAR",
        skip_deploy=True,
    )
    assert result == b"true"
    result, gas_burnt = near.test_method(
        __file__,
        "nft_revoke_all",
        json.dumps({"token_id": "0"}),
        attached_deposit="1 yNEAR",
        skip_deploy=True,
    )
    assert result == b""
    result, gas_burnt = near.test_method(
        __file__,
        "nft_is_approved",
        json.dumps({"token_id": "0", "approved_account_id": approved_account_id}),
        attached_deposit="1 yNEAR",
        skip_deploy=True,
    )
    assert result == b"false"

