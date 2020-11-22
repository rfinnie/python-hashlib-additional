#!/usr/bin/env python3

import unittest
import hashlib_additional
import hashlib


class BaseTest:
    name = ""
    empty_digest = b""
    foo_digest = b""
    foobar_digest = b""
    large_digest = b""

    def test_empty(self):
        self.assertEqual(
            hashlib_additional.new(self.name).digest(),
            self.empty_digest,
        )

    def test_foo(self):
        self.assertEqual(
            hashlib_additional.new(self.name, b"foo").digest(),
            self.foo_digest,
        )

    def test_foo_hexdigest(self):
        self.assertEqual(
            hashlib_additional.new(self.name, b"foo").hexdigest(),
            self.foo_hexdigest,
        )

    def test_foobar(self):
        self.assertEqual(
            hashlib_additional.new(self.name, b"foobar").digest(),
            self.foobar_digest,
        )

    def test_same(self):
        digest = hashlib_additional.new(self.name, b"foobar")
        self.assertEqual(
            digest.digest(),
            digest.digest(),
        )

    def test_update(self):
        digest = hashlib_additional.new(self.name, b"foo")
        digest.update(b"bar")
        self.assertEqual(
            digest.digest(),
            self.foobar_digest,
        )

    def test_same_update_none(self):
        digest = hashlib_additional.new(self.name, b"foobar")
        old_result = digest.digest()
        digest.update(b"")
        self.assertEqual(
            digest.digest(),
            old_result,
        )

    def test_copy_new_changed(self):
        digest = hashlib_additional.new(self.name, b"foo")
        digest_copy = digest.copy()
        digest_copy.update(b"bar")
        self.assertEqual(
            digest_copy.digest(),
            self.foobar_digest,
        )

    def test_copy_old_unchanged(self):
        digest = hashlib_additional.new(self.name, b"foo")
        digest_copy = digest.copy()
        digest_copy.update(b"bar")
        digest_copy.digest()
        self.assertEqual(
            digest.digest(),
            self.foo_digest,
        )

    def test_direct(self):
        digest = getattr(hashlib_additional, self.name)()
        digest.update(b"foo")
        self.assertEqual(
            digest.digest(),
            self.foo_digest,
        )

    def test_large(self):
        digest = hashlib_additional.new(self.name)
        sha = hashlib.sha256()
        for i in range(1024):
            fragment = sha.digest()
            digest.update(fragment)
            sha.update(fragment)
        self.assertEqual(
            digest.digest(),
            self.large_digest,
        )


class TestAdler32(unittest.TestCase, BaseTest):
    name = "adler32"
    empty_digest = b"\x00\x00\x00\x01"
    foo_digest = b"\x02\x82\x01E"
    foo_hexdigest = "02820145"
    foobar_digest = b"\x08\xab\x02z"
    large_digest = b"l9\xbe\xe2"


class TestBsd(unittest.TestCase, BaseTest):
    name = "bsd"
    empty_digest = b"\x00\x00"
    foo_digest = b"\x00\xc0"
    foo_hexdigest = "00c0"
    foobar_digest = b"\x00\xd3"
    large_digest = b"S\x85"


class TestCksum(unittest.TestCase, BaseTest):
    name = "cksum"
    empty_digest = b"\xff\xff\xff\xff"
    foo_digest = b"\x93;\x9e\x91"
    foo_hexdigest = "933b9e91"
    foobar_digest = b"\x9b]\x95\xd6"
    large_digest = b"\xab\x1d\x12\xa7"


class TestCrc32(unittest.TestCase, BaseTest):
    name = "crc32"
    empty_digest = b"\x00\x00\x00\x00"
    foo_digest = b"\x8cse!"
    foo_hexdigest = "8c736521"
    foobar_digest = b"\x9e\xf6\x1f\x95"
    large_digest = b"\xd6\xec\x16\xac"


class TestNull(unittest.TestCase, BaseTest):
    name = "null"
    empty_digest = b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    foo_digest = b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    foo_hexdigest = "00000000000000000000000000000000"
    foobar_digest = b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    large_digest = b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"

    def test_variable_digest_size(self):
        digest = hashlib_additional.new(self.name, b"foo", digest_size=3)
        self.assertEqual(
            digest.digest(),
            b"\x00\x00\x00",
        )


class TestSysv(unittest.TestCase, BaseTest):
    name = "sysv"
    empty_digest = b"\x00\x00"
    foo_digest = b"\x01D"
    foo_hexdigest = "0144"
    foobar_digest = b"\x02y"
    large_digest = b"\xbbo"


class TestTwoping(unittest.TestCase, BaseTest):
    name = "twoping"
    empty_digest = b"\xff\xff"
    foo_digest = b"*\x90"
    foo_hexdigest = "2a90"
    foobar_digest = b"\xc8\xbb"
    large_digest = b"A\x93"

    def test_0000_to_ffff(self):
        """Test \x00\x00 to \xff\xff swap"""
        digest = hashlib_additional.new(self.name, b"\x25\xe6\xda\x19")
        self.assertEqual(
            digest.digest(),
            b"\xff\xff",
        )


class TestUdp(unittest.TestCase, BaseTest):
    name = "udp"
    empty_digest = b"\xff\xff"
    foo_digest = b"o\xd5"
    foo_hexdigest = "6fd5"
    foobar_digest = b"D7"
    large_digest = b"l\xbe"


class TestRandom(unittest.TestCase):
    name = "random"

    def test_empty(self):
        self.assertEqual(
            len(hashlib_additional.new(self.name).digest()),
            16,
        )

    def test_foo(self):
        self.assertEqual(
            len(hashlib_additional.new(self.name, b"foo").digest()),
            16,
        )

    def test_same(self):
        digest = hashlib_additional.new(self.name, b"foobar")
        self.assertEqual(
            digest.digest(),
            digest.digest(),
        )

    def test_variable_digest_size(self):
        digest = hashlib_additional.new(self.name, b"foo", digest_size=3)
        self.assertEqual(
            len(digest.digest()),
            3,
        )

    def test_direct(self):
        digest = hashlib_additional.random()
        digest.update(b"foo")
        self.assertEqual(
            len(digest.digest()),
            16,
        )


class TestHashlibAdditional(unittest.TestCase):
    def test_algorithms_available(self):
        self.assertEqual(
            hashlib_additional.algorithms_available,
            {
                "adler32",
                "bsd",
                "cksum",
                "crc32",
                "null",
                "random",
                "sysv",
                "twoping",
                "udp",
            },
        )

    def test_algorithms_guaranteed(self):
        self.assertEqual(
            hashlib_additional.algorithms_guaranteed,
            hashlib_additional.algorithms_available,
        )

    def test___all__(self):
        self.assertEqual(
            sorted(hashlib_additional.__all__),
            sorted(
                list(hashlib_additional.algorithms_available)
                + ["new", "algorithms_available", "algorithms_guaranteed"]
            ),
        )

    def test_new_invalid_algorithm(self):
        with self.assertRaises(ValueError):
            hashlib_additional.new("badalgorithm")
