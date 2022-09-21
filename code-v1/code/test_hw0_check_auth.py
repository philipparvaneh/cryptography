"""
test_hw0_check_auth.py
"""

from hw0_basic_check import check_auth


def test_check_auth():
    try:
        check_auth()
    except Exception as e:
        print(e)
        exit(-1)
