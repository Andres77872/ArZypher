import random
import hashlib
import secrets
import base64


def pad(value: str, max_length: int) -> str:
    """
    Complete the binary string with zeros at the right if max_length is bigger the return a substring

    :param value: Binary string
    :param max_length: Max length
    :return: String with the length of max_length
    """
    return value[:max_length].zfill(max_length)


def generate_hashcode(key_string: str, max_length: int):
    dg = hashlib.sha256(key_string.encode()).digest()
    return format(int.from_bytes(dg, 'big'), 'b')[:max_length].zfill(max_length)


def xor(params_keys: list[int], params: list[int] | str) -> str:
    # XOR operation
    if isinstance(params, list):
        return ''.join([f"{p ^ random.getrandbits(k):0{k}b}" for p, k in zip(params, params_keys)])
    else:
        _r = []
        _c = 0
        for k in params_keys:
            _r.append(f"{int(params[_c:_c + k], 2) ^ random.getrandbits(k):0{k}b}")
            _c += k
        return ''.join(_r)


def arzypher_encoder(private_key: str | None,
                     random_key: int | None,
                     check_sum: int | None,
                     padding: int | bool | None,
                     params_keys: list[int],
                     params_data: list[int]) -> tuple[str, int | None]:
    """
    Generate Base64 code from int type data.

    **private_key** must be a strong string password, this will be used only if the **check_sum**
    is not None.

    If **random_key** is None or zero, the token generated always will be the same, this is util
    to generate URL with an image ID or another data that doesn't matter if the content is visible,
    also the token generated will have fewer characters.

    If **check_sum** is None or zero, then the values can be edited by the user and will accept any
    token if it has a compatible format with the **params_keys**. If the token is compatible and was
    deserialized, and the **random_key** is not Null or zero, the decrypted value will be an unexpected
    value from 0-2^key_value but if both are None or zero the token will be just the **params_data** in
    base64.

    The **padding** is not implemented yet

    :param private_key: ServerSide private key.
    :param random_key: (Optional) Bytes length for the random key, the Base64 code will be different each time.
    :param check_sum: (Optional) The Base64 will check the integrity before decoded, max value 256 (SHA256).
    :param padding: Not implemented yet.
    :param params_keys: List with the byte length for each data.
    :param params_data: List with the ints to be encoded.
    :return: Base64 string coded to be used as URL.
    """

    if check_sum is not None and (check_sum > 256 or check_sum < 0):
        return "", None

    for x, y in zip(params_keys, params_data):
        if x <= 0 or 2 ** x - 1 < y:
            return '', None

    binary_randomkey_string = ''
    raw_seed_int = None

    # Generate the binary random key string
    if random_key is not None and random_key != 0:
        raw_seed_int = secrets.randbits(random_key)
        # Initialize the native python random generator with the raw_seed_int
        random.seed(raw_seed_int)
        binary_randomkey_string = f"{raw_seed_int:0{random_key}b}"
        binary_params_string = xor(params_keys, params_data)
    else:
        # Generate a binary string with all params
        binary_params_string = ''.join([f"{p:0{k}b}" for p, k in zip(params_data, params_keys)])
        random_key = 0

    if not isinstance(check_sum, int):
        check_sum = 0

    # Generate a fix_length
    # sm = check_sum + random_key + sum(params_keys)
    # fix_length = (24 - sm % 24) % 24

    dg = ''
    if check_sum != 0:
        if not isinstance(private_key, str):
            private_key = ''
        _k = (binary_randomkey_string +
              binary_params_string +
              ''.join(map(str, params_keys)) +
              generate_hashcode(private_key, 256))
        dg = generate_hashcode(_k, check_sum)

    res = binary_randomkey_string + dg + binary_params_string

    key = bytes([int(res[i:i + 8], 2) for i in range(0, len(res), 8)])
    b64 = base64.b64encode(key, altchars=b'_-')

    return b64.decode('utf-8'), raw_seed_int


def arzypher_decoder(private_key: str | None,
                     random_key: int | None,
                     check_sum: int | None,
                     padding: int | bool | None,
                     params_keys: list[int],
                     encoded: str) -> tuple[list[int], int | None]:
    """
    Decode a Base64 encoded with 'cph_encode',
    All params must be the same as the used in the encoded method.

    :param private_key:
    :param random_key: (Optional) Bytes length for the random key, the Base64 code will be different each time.
    :param check_sum: (Optional) The Base64 will check the integrity before decode.
    :param padding: Not implemented yet.
    :param params_keys: List with the byte length for each data.
    :param encoded: Base64 encoded
    :return: List of int with the data decoded
    """
    if check_sum is not None and (check_sum > 256 or check_sum < 0):
        return [0], None

    if random_key is None:
        random_key = 0
    if check_sum is None:
        check_sum = 0

    sm = random_key + check_sum + sum(params_keys)

    # Decode base64 and convert to binary string
    d = base64.b64decode(encoded, altchars=b'_-')
    res = ''.join(['{:08b}'.format(i) for i in d])[-sm:]

    # Extract random seed and ciphertext
    if random_key is not None and random_key != 0:
        s = res[:random_key]
        raw_seed = int(s, 2)
        t = res[random_key:]
        random.seed(raw_seed)
    else:
        s = ''
        raw_seed = None
        random_key = 0
        t = res

    # Calculate checksum
    if check_sum is not None and check_sum != 0:
        # fix_length = 24 - (sm % 24)
        if not isinstance(private_key, str):
            private_key = ''
        hs = t[: check_sum]
        k = s + t[check_sum:sm] + ''.join([str(x) for x in params_keys]) + generate_hashcode(private_key, 256)
        dg = generate_hashcode(k, check_sum)
        if dg != hs:
            # print(dg, hs)
            return [0], None
        t = t[check_sum:]
    # else:
    #     fix_length = 24 - (sm % 24)
    #     t = t[:fix_length]

    # Decrypt ciphertext
    rk = xor(params_keys, t) if random_key != 0 else t

    # Extract plaintext from decrypted ciphertext
    res = []
    t = rk
    for i in params_keys:
        res.append(int(t[:i], 2))
        t = t[i:]

    return res, raw_seed
