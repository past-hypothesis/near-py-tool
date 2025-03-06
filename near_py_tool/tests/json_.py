import near
import json


@near.export
def json_loads():
    near.value_return(str(len(list(json.loads(near.input()).keys()))))


@near.export
def json_roudntrip():
    near.value_return(json.dumps(json.loads(near.input())))


def test_json():
    input = {"key1": "value1", "key2": 2, "key3": False}
    result, gas_burnt = near.test_method(__file__, "json_loads", input)
    assert result == b"3"
    result, gas_burnt = near.test_method(__file__, "json_roudntrip", input, skip_deploy=True)
    # assert decoded.decode("ascii") == input_string
