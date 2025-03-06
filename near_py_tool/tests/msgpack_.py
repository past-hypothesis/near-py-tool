import near
import msgpack
import json

test_input = {
    "key1": "value1",
    "key2": 1234,
    "key3": False,
    "key4": {
        "key11": "value11",
        "key12": 12345,
    },
    "key5": [1, 2, "3", None, True, False, {"key6": "value6"}],
}


@near.export
def msgpack_packb():
    near.value_return(msgpack.packb(test_input))


@near.export
def msgpack_unpackb():
    result = msgpack.unpackb(near.input())
    near.log_utf8(json.dumps(result))
    near.value_return(str(len(list(result.keys()))))


@near.export
def msgpack_roudntrip():
    value = msgpack.unpackb(near.input())
    near.log_utf8(json.dumps(value))
    near.value_return(msgpack.packb(value))
    # near.value_return(msgpack.packb(msgpack.unpackb(near.input())))


@near.export
def msgpack_bigint():
    # bigint support uses MessagePack extension type (81), so it has to be tested inside the WASM environment
    # as the host's msgpack module doesn't support this out of the box
    test_input_with_bigint = {
        "key1": 2**32 - 1,
        "key2": 2**64 - 1,
        "key3": 2**123,
        "key4": 2**1024 - 1,
    }
    near.log_utf8(json.dumps(test_input_with_bigint))
    result = msgpack.unpackb(msgpack.packb(test_input_with_bigint))
    near.log_utf8(json.dumps(result))
    if result != test_input_with_bigint:
        near.panic_utf8("msgpack_bigint(): result comparison failed")


def test_msgpack():
    # result, gas_burnt = near.test_method(__file__, "msgpack_packb", {})
    # assert msgpack.unpackb(result) == test_input
    # result, gas_burnt = near.test_method(__file__, "msgpack_unpackb", msgpack.packb(test_input), skip_deploy=True)
    # assert result == b"5"
    result, gas_burnt = near.test_method(
        __file__, "msgpack_roudntrip", msgpack.packb(test_input)
    )  # , skip_deploy=True)
    assert msgpack.unpackb(result) == test_input
    result, gas_burnt = near.test_method(__file__, "msgpack_bigint", {}, skip_deploy=True)
