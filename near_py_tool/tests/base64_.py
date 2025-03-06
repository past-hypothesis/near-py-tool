import near
import base64


@near.export
def base64_encode():
    near.value_return(base64.b64encode(near.input()))


@near.export
def base64_decode():
    near.log_utf8(near.input().decode("ascii"))
    near.value_return(base64.b64decode(near.input().decode("ascii")))


def test_base64():
    input_string = "an input string"
    encoded, gas_burnt = near.test_method(__file__, "base64_encode", input_string)
    assert encoded == b"YW4gaW5wdXQgc3RyaW5n"
    decoded, gas_burnt = near.test_method(__file__, "base64_decode", encoded.decode("ascii"), skip_deploy=True)
    assert decoded.decode("ascii") == input_string
