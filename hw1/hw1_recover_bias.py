from unittest import result
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
    byteArr = bytearray(20)
    results = []
    tracker = [0]*100
    for i in range(100):
        results.append(bias_encryption_oracle(bytes(byteArr)))
    for j in range(100):
        tracker[j] = [results[j].hex()[i:i+2] for i in range(0,len(results[j].hex()), 2)]
    num = [0]*20
    hexNum = 0
    hexList = [0]*100
    for i in range(100):
        for k in range(100):
            for j in range(20):
                if tracker[i][j] == tracker[k][j]:
                    num[j] += 1
    maxCounter = 0
    idx = 0
    for i in range(20):
        if num[i] > maxCounter:
            maxCounter = num[i]
            idx = i
    for i in range(100):
        hexList[i] = tracker[i][idx]
    hexDict = dict()
    for i in range(100):
        if tracker[i][idx] in hexDict:
            hexDict[tracker[i][idx]] += 1
        else:
            hexDict[tracker[i][idx]] = 1
    hexNum = max(hexDict, key=hexDict.get)        

    print(hexNum)
    print(idx)
    byteFlag = bytearray(10)
    for i in range(10):
        byteArr = bytearray(13 - i)
        newResult = ""
        newTracker = []
        for j in range(100):
            newResult = bias_encryption_oracle(bytes(byteArr))
            newList = [newResult.hex()[k : k + 2] for k in range(0, len(newResult.hex()), 2)]
            newTracker.append(newList)
        num = dict()
        for l in range(100):
            for k in range(100):
                if newTracker[l][idx] == newTracker[k][idx]:
                    if newTracker[l][idx] in num:
                        num[newTracker[l][idx]] += 1
                    else:
                        num[newTracker[l][idx]] = 1
        byteNum = max(num, key=num.get)
        #print(byteNum)
        hexStr = hex(int(byteNum, 16) ^ int(hexNum, 16))
        #print(hexStr)
        byteFlag[i] = int(hexStr, 16)
        #print(byteFlag)

    flag = bytes(byteFlag)
    print(flag)
    return flag



if __name__ == "__main__":

    try:
        check_auth()
    except Exception as e:
        print(e)
        exit(-1)

    flag = recover_flag()
    print(flag.decode())
