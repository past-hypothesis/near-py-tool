import json
import near


def json_syntax_error_inner():
    json.loads("~inner~")


def json_syntax_error_nested_inner():
    try:
        json.loads("~immediate~")
    except Exception as e:
        near.log_utf8(f"json_syntax_error_nested_inner(): json.loads(): exception: {e}")
    try:
        json_syntax_error_inner()
    except Exception as e:
        near.log_utf8(f"json_syntax_error_nested_inner(): json_syntax_error_inner(): exception: {e}")
    near.log_utf8(f"json_syntax_error_nested_inner(): done")
    near.value_return(b"success")


@near.export
def json_syntax_error_nested():
    json_syntax_error_nested_inner()


@near.export
def json_syntax_error():
    try:
        json.loads("~immediate~")
    except Exception as e:
        near.log_utf8(f"json_syntax_error(): json.loads(): exception: {e}")
    try:
        json_syntax_error_inner()
    except Exception as e:
        near.log_utf8(f"json_syntax_error(): json_syntax_error_inner(): exception: {e}")
    near.log_utf8(f"json_syntax_error(): done")
    near.value_return(b"success")


@near.export
def key_error_immediate():
    m = {"another_key": "value"}
    try:
        # note: MicroPython seems to raise TypeError instead of KeyError here
        near.log_utf8(m["key"])
    except Exception as e:
        near.log_utf8(f"get(): {type(e)}: {e}")
        near.value_return(b"default")


def get_(self, key, default=None):
    try:
        # note: MicroPython seems to raise TypeError instead of KeyError here
        return self[key]
    except Exception as e:
        near.log_utf8(f"get_({self}, {key}, {default}): {type(e)}: {e}, returning {default}")
        return default


@near.export
def key_error_nested():
    m = {"another_key": "value"}
    result = get_(m, "key", "default")
    near.value_return(result)


# note: this fails with NEAR_ABORT() called by nlr_jump_fail() (main.c:289)
@near.export
def key_error_combined():
    m = {"another_key": "value"}
    try:
        near.log_utf8(m["key"])
    except Exception as e:
        near.log_utf8(f"get(): {type(e)}: {e}")
    result = get_(m, "key", "default")
    near.value_return(result)


# note: this fails with NEAR_ABORT() called by nlr_jump_fail() (main.c:289)
@near.export
def key_error_combined_reverse():
    m = {"another_key": "value"}
    result = get_(m, "key", "default")
    try:
        near.log_utf8(m["key"])
    except Exception as e:
        near.log_utf8(f"get(): {type(e)}: {e}")
    near.value_return(result)


def test_json_syntax_error_nested():
    result, gas_burnt = near.test_method(__file__, "json_syntax_error_nested", {})
    assert result == b"success"


def test_json_syntax_error():
    result, gas_burnt = near.test_method(__file__, "json_syntax_error", {})
    assert result == b"success"


def test_key_error_immediate():
    result, gas_burnt = near.test_method(__file__, "key_error_immediate", {})
    assert result == b"default"


def test_key_error_nested():
    result, gas_burnt = near.test_method(__file__, "key_error_nested", {})
    assert result == b"default"


# # note: this fails with NEAR_ABORT() called by nlr_jump_fail() (main.c:289)
# def test_key_error_combined():
#     result, gas_burnt = near.test_method(__file__, "key_error_combined", {})
#     assert result == b"default"

# # note: this fails with NEAR_ABORT() called by nlr_jump_fail() (main.c:289)
# def test_key_error_combined_reverse():
#     result, gas_burnt = near.test_method(__file__, "key_error_combined_reverse", {})
#     assert result == b"default"

