import random, string, base64, urllib.parse

PAYLOAD_ENCODERS = {
    "raw": lambda s: s,
    "url": lambda s: urllib.parse.quote(s, safe=""),
    "double_url": lambda s: urllib.parse.quote(urllib.parse.quote(s, safe=""), safe=""),
    "b64": lambda s: base64.b64encode(s.encode()).decode(),
    "hex": lambda s: "".join("%%%02x" % ord(c) for c in s),
    "unicode": lambda s: "".join("\\u%04x" % ord(c) for c in s),
}

def mutate_param_name(name: str) -> list:
    return [
        name,
        name.upper(),
        name.lower(),
        name.capitalize(),
        name + "[]",
        name + "=",
        "_" + name,
        name + "_",
    ]

def mutate_value(value: str) -> list:
    return [
        value,
        "'" + value + "'",
        '"' + value + '"',
        value.upper(),
        value.lower(),
        value + " ",
        "\t" + value,
        "\n" + value,
        "\r" + value,
        " " + value + " ",
    ]

def encode_payload(payload: str, method: str = "raw") -> str:
    encoder = PAYLOAD_ENCODERS.get(method, PAYLOAD_ENCODERS["raw"])
    return encoder(payload)

def inject_at_position(base: str, inject: str, pos: str = "suffix") -> str:
    if pos == "prefix":
        return inject + base
    elif pos == "suffix":
        return base + inject
    elif pos == "replace":
        return inject
    else:
        return base + inject

def random_string(length: int = 8) -> str:
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=length))
