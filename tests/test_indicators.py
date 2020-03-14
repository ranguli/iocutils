import pytest
from lib.indicators import extract_indicators 
from typing import TextIO

def test_extract_indicatorss_union_accepts_strings():
    assert extract_indicators("foo") == "foo"

def test_extract_indicatorss_union_accepts_fp(tmp_path):
    d = tmp_path
    p = d / "foo.txt" 
    p.write_text("")

    with open(p) as fp:
        assert extract_indicators(fp) == fp
