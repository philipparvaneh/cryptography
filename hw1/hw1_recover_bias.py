import requests

import config as cfg


def xor(a: bytes, b: bytes) -> bytes:
    assert len(a) == len(b), f"xor given bytes of unequal length. {len(a)=} {len(b)=}"
    return bytes(a ^ b for a, b in zip(a, b))


def check_auth():
    res = requests.get(cfg.AUTH_URL, auth=(cfg.usr, cfg.key))
    if res.text != f"auth succeeded for {cfg.usr}":
        raise Exception(
            f"failed to authenticate with the server\nplease ensure that you set the username and API key correctly in the python script\n\ngot error: {res.text}\n"
        )


def bias_encryption_oracle(pt: bytes) -> bytes:
    res = requests.get(cfg.BIAS_URL, auth=(cfg.usr, cfg.key), params={"pt": pt.hex()})
    try:
        return bytes.fromhex(res.text)
    except Exception as e:
        print(
            f"Server Error: The server failed to process the request, and produced the following output. Please do not be alarmed and share the output with the TAs on Slack so they can debug the error.\n\n{res.text}"
        )
        exit(-1)


def recover_flag() -> bytes:
    flag = bytes()

    # TODO: fill in your answer here
    #First, you can figure out the bias by sending a bunch of queries with the same message, storing the
    #outputs in an array, and then analyzing it. Second, once you know the position of the biased bit,
    #you can vary the message length to position bytes of the FLAG one-by-one over the biased position
    #to recover it.
    arr = bytearray(20)
    results = []
    for x in range[30]:
        results.append(bias_encryption_oracle(bytes(arr)))    

    print(results)
    return flag


if __name__ == "__main__":

    try:
        check_auth()
    except Exception as e:
        print(e)
        exit(-1)

    flag = recover_flag()
    print(flag.decode())
