import random
import hashlib
import secrets
import base64
import hmac


def pad(value: str, max_length: int) -> str:
    """
    Complete the binary string with zeros at the right if max_length is bigger the return a substring

    :param value: Binary string
    :param max_length: Max length
    :return: String with the length of max_length
    """
    return value[:max_length].zfill(max_length)


def generate_hashcode(secret_key: str, key_string: str, max_length: int):
    if max_length <= 256:
        _h = hashlib.sha256
    elif max_length <= 384:
        _h = hashlib.sha384
    else:
        _h = hashlib.sha512

    secret_key = secret_key if secret_key else ''

    dg_hmac = hmac.new(secret_key.encode('utf-8'), key_string.encode("utf-8"), _h).digest()

    return format(int.from_bytes(dg_hmac, 'big'), 'b')[:max_length].zfill(max_length)


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
                     params_keys: list[int] | list[list[type[str | int], int]],
                     params_data: list[int] | list[str]) -> tuple[str, int | None]:
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
    :param check_sum: (Optional) The Base64 will check the integrity before decoded, max value 512 (SHA512).
    :param padding: Not implemented yet.
    :param params_keys: List with the byte length for each data.
    :param params_data: List with the ints to be encoded.
    :return: Base64 string coded to be used as URL.
    """

    if check_sum is not None and (check_sum > 512 or check_sum < 0):
        return '', None

    if not isinstance(check_sum, int):
        check_sum = 0

    if not isinstance(random_key, int):
        random_key = 0

    # if not isinstance(private_key, str):
    #     private_key = ''

    _params_data = []
    _params_keys = []
    for pk, pd in zip(params_keys, params_data):
        if isinstance(pd, int) and isinstance(pk, int):
            _params_data.append(pd)
            _params_keys.append(pk)
        elif isinstance(pk, list):
            _params_keys.append(pk[1])
            if pk[0] in {str, int}:
                if pk[0] == str:
                    _b = bytes(pd[:pk[1] // 8], 'utf-8')
                    _params_data.append(int.from_bytes(_b, 'big'))
                elif pk[0] == int:
                    _params_data.append(pd)
            else:
                return '', None
        else:
            return '', None
    params_data = _params_data
    params_keys = _params_keys

    del _params_data
    del _params_keys

    for x, y in zip(params_keys, params_data):
        if x <= 0 or 2 ** x - 1 < y:
            return '', None

    # Generate a fix_length
    sm = check_sum + random_key + sum(params_keys)

    fix_length = sm % 8
    if fix_length:
        params_keys.append(8 - fix_length)
        params_data.append(0)

    # print(params_keys)
    # print(params_data)

    binary_randomkey_string = ''
    raw_seed_int = 0

    # Generate the binary random key string
    if random_key is not None and random_key != 0:
        raw_seed_int += secrets.randbits(random_key)
        binary_randomkey_string = f"{raw_seed_int:0{random_key}b}"
    if private_key is not None:
        raw_seed_int += int.from_bytes(hashlib.sha256(private_key.encode('utf-8')).digest(), 'big')

    if raw_seed_int != 0:
        # Initialize the native python random generator with the raw_seed_int
        random.seed(raw_seed_int)
        binary_params_string = xor(params_keys, params_data)
    else:
        # Generate a binary string with all params
        binary_params_string = ''.join([f"{p:0{k}b}" for p, k in zip(params_data, params_keys)])

    # print(binary_params_string)

    dg = ''
    if check_sum != 0:
        _k = (binary_randomkey_string +
              binary_params_string +
              ''.join(map(str, params_keys)))
        dg = generate_hashcode(private_key, _k, check_sum)
        # print(_k)
    res = binary_randomkey_string + dg + binary_params_string

    key = bytes([int(res[i:i + 8], 2) for i in range(0, len(res), 8)])
    b64 = base64.b64encode(key, altchars=b'_-')
    b64 = b64.decode('utf-8')
    b64 = b64.replace('=', '')

    return b64, raw_seed_int


def arzypher_decoder(private_key: str | None,
                     random_key: int | None,
                     check_sum: int | None,
                     padding: int | bool | None,
                     params_keys: list[int] | list[list[type[str | int], int]],
                     encoded: str) -> tuple[list[int] | list[str], int | None]:
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
    if check_sum is not None and (check_sum > 512 or check_sum < 0):
        return [0], None

    if len(encoded) % 4 == 1:
        return [0], None

    padding_fix = (4 - len(encoded) % 4) % 4
    encoded = encoded + "=" * padding_fix if padding_fix else encoded

    if random_key is None:
        random_key = 0
    if check_sum is None:
        check_sum = 0

    _params_keys = []
    _pd = []
    for pk in params_keys:
        if isinstance(pk, int):
            _params_keys.append(pk)
            _pd.append(int)
        elif isinstance(pk, list):
            if pk[0] in {str, int}:
                _params_keys.append(pk[1])
                _pd.append(pk[0])
            else:
                return [0], None
        else:
            return [0], None

    params_keys = _params_keys

    # print(params_keys)
    # print(_pd)

    del _params_keys

    sm = random_key + check_sum + sum(params_keys)

    # Generate a fix_length
    _fx = False
    fix_length = sm % 8
    if fix_length:
        params_keys.append(8 - fix_length)
        _fx = True
        sm += 8 - fix_length

    # print(params_keys)

    # Decode base64 and convert to binary string
    d = base64.b64decode(encoded, altchars=b'_-')
    res = ''.join(['{:08b}'.format(i) for i in d])[-sm:]

    # print(''.join(['{:08b}'.format(i) for i in d]))

    raw_seed = 0

    # Extract random seed and ciphertext
    if random_key is not None and random_key != 0:
        s = res[:random_key]
        raw_seed += int(s, 2)
        t = res[random_key:]
    else:
        s = ''
        t = res

    if private_key is not None:
        raw_seed += int.from_bytes(hashlib.sha256(private_key.encode('utf-8')).digest(), 'big')

    if raw_seed != 0:
        random.seed(raw_seed)

    # Calculate checksum
    if check_sum is not None and check_sum != 0:
        # fix_length = 24 - (sm % 24)
        if not isinstance(private_key, str):
            private_key = ''
        hs = t[: check_sum]
        k = s + t[check_sum:sm] + ''.join([str(x) for x in params_keys])

        # print(t[check_sum:sm])

        dg = generate_hashcode(private_key, k, check_sum)
        if dg != hs:
            # print(dg)
            # print(hs)
            return [0], None
        t = t[check_sum:]

    # Decrypt ciphertext
    rk = xor(params_keys, t) if raw_seed != 0 else t

    # Extract plaintext from decrypted ciphertext
    res = []
    t = rk

    for i, _p in zip(params_keys, _pd):
        _di = int(t[:i], 2)
        res.append(_di if _p == int else _di.to_bytes(len(t[:i]) // 8, 'big').decode('utf-8'))
        t = t[i:]

    return res, raw_seed
