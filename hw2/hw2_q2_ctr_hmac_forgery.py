import requests
import requests_cache
import time

import config as cfg
import hashlib

BLOCK_BYTES = 16


def xor(a: bytes, b: bytes) -> bytes:
    assert len(a) == len(b), f"xor given bytes of unequal length. {len(a)=} {len(b)=}"
    return bytes(a ^ b for a, b in zip(a, b))


def check_auth():
    res = requests.get(cfg.AUTH_URL, auth=(cfg.usr, cfg.key))
    if res.text != f"auth succeeded for {cfg.usr}":
        raise Exception(
            f"failed to authenticate with the server\nplease ensure that you set the username and API key correctly in the python script\n\ngot error: {res.text}\n"
        )


def genCookie_oracle() -> bytes:
    res = requests.get(cfg.Q2_GENCOOKIE_URL, auth=(cfg.usr, cfg.key))
    try:
        return bytes.fromhex(res.text)
    except Exception as e:
        print(
            f"Server Error: The server failed to process the request, and produced the following output. Please do not be alarmed and share the output with the TAs on Slack so they can debug the error.\n\n{res.text}"
        )
        exit(-1)


def isCookieAdFree_oracle(ct: bytes) -> bool:
    res = requests.get(
        cfg.Q2_ADFREE_URL, auth=(cfg.usr, cfg.key), params={"ct": ct.hex()}
    )
    if res.text == "true":
        return True
    elif res.text == "false":
        return False
    else:
        print(
            f"Server Error: The server failed to process the request, and produced the following output. Please do not be alarmed and share the output with the TAs on Slack so they can debug the error.\n\n{res.text}"
        )
        exit(-1)


def gen_cookie_ad_free() -> bytes:
    timestamp = "0" * 10

    # TODO: fill in your answer here
    pass


if __name__ == "__main__":

    try:
        check_auth()
    except Exception as e:
        print(e)
        exit(-1)

    cookie_ad_free = gen_cookie_ad_free()
    if isCookieAdFree_oracle(cookie_ad_free):
        print("Forged AdFree cookie ciphertext:", cookie_ad_free.hex())
    else:
        print("Failed to forge AdFree cookie ciphertext")
