# SPDX-PackageName: python-hashlib-additional
# SPDX-PackageSupplier: Ryan Finnie <ryan@finnie.org>
# SPDX-PackageDownloadLocation: https://github.com/rfinnie/python-hashlib-additional
# SPDX-FileCopyrightText: © 2019 Ryan Finnie <ryan@finnie.org>
# SPDX-License-Identifier: MIT

import io
import hashlib
import unittest

import hashlib_additional


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

    def test_digest_size(self):
        digest = hashlib_additional.new(self.name)
        self.assertEqual(
            len(digest.digest()),
            digest.digest_size,
        )

    @unittest.skipUnless(hasattr(hashlib, "file_digest"), "Older stdlib")
    def test_file_digest(self):  # pragma: no cover
        """
        Test if file_digest, which expects a hashlib-like interface,
        can actually use a hashlib-like interface
        """
        hash = getattr(hashlib_additional, self.name)
        digest = hashlib.file_digest(io.BytesIO(b"foo"), hash)
        self.assertEqual(
            digest.digest(),
            self.foo_digest,
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


class TestFletcher16(unittest.TestCase, BaseTest):
    name = "fletcher16"
    empty_digest = b"\x00\x00"
    foo_digest = b"\x81E"
    foo_hexdigest = "8145"
    foobar_digest = b"\xad{"
    large_digest = b"\xe9+"


class TestFletcher32(unittest.TestCase, BaseTest):
    name = "fletcher32"
    empty_digest = b"\x00\x00\x00\x00"
    foo_digest = b"\xdf;o\xd5"
    foo_hexdigest = "df3b6fd5"
    foobar_digest = b"\x85sD7"
    large_digest = b"\xd2Cl\xbe"


class TestFletcher64(unittest.TestCase, BaseTest):
    name = "fletcher64"
    empty_digest = b"\x00\x00\x00\x00\x00\x00\x00\x00"
    foo_digest = b"\x00oof\x00oof"
    foo_hexdigest = "006f6f66006f6f66"
    foobar_digest = b"\xc4\xdfQ-bo\xe1\xc7"
    large_digest = b"L\xa6\x97&\xf5fwW"


class TestSdbm(unittest.TestCase, BaseTest):
    name = "sdbm"
    empty_digest = b"\x00\x00\x00\x00"
    foo_digest = b"\x32\xa9\x49\x26"
    foo_hexdigest = "32a94926"
    foobar_digest = b"\xa6\x43\x7b\x0d"
    large_digest = b"\x9f\x8a\xdb\x84"


class TestDjb2(unittest.TestCase, BaseTest):
    name = "djb2"
    empty_digest = b"\x00\x00\x15\x05"
    foo_digest = b"\x0b\x88\x73\x89"
    foo_hexdigest = "0b887389"
    foobar_digest = b"\xfd\xe4\x60\xbe"
    large_digest = b"\x76\x2c\x24\xb5"


class TestFNV0(unittest.TestCase, BaseTest):
    name = "fnv0"
    empty_digest = b"\x00\x00\x00\x00"
    foo_digest = b"\x8f\xfd\x6e\x28"
    foo_hexdigest = "8ffd6e28"
    foobar_digest = b"\xb7\x4b\xb5\xef"
    large_digest = b"\xc7\x94\xe4\xa0"


class TestFNV1(unittest.TestCase, BaseTest):
    name = "fnv1"
    empty_digest = b"\x81\x1c\x9d\xc5"
    foo_digest = b"\x40\x8f\x5e\x13"
    foo_hexdigest = "408f5e13"
    foobar_digest = b"\x31\xf0\xb2\x62"
    large_digest = b"\xd5\x9d\x63\xc5"

    def test_large_digest_size(self):
        digest = hashlib_additional.new(self.name, b"foo", digest_size=128)
        self.assertEqual(
            len(digest.digest()),
            128,
        )

    def test_invalid_digest_size(self):
        with self.assertRaises(ValueError):
            hashlib_additional.new(self.name, digest_size=3)


class TestFNV1a(unittest.TestCase, BaseTest):
    name = "fnv1a"
    empty_digest = b"\x81\x1c\x9d\xc5"
    foo_digest = b"\xa9\xf3\x7e\xd7"
    foo_hexdigest = "a9f37ed7"
    foobar_digest = b"\xbf\x9c\xf9\x68"
    large_digest = b"\x89\xd2\x64\xc5"


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
                "djb2",
                "fletcher16",
                "fletcher32",
                "fletcher64",
                "fnv0",
                "fnv1",
                "fnv1a",
                "null",
                "random",
                "sdbm",
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
            sorted(list(hashlib_additional.algorithms_available) + ["new", "algorithms_available", "algorithms_guaranteed"]),
        )

    def test_new_invalid_algorithm(self):
        with self.assertRaises(ValueError):
            hashlib_additional.new("badalgorithm")


class TestBePack(unittest.TestCase):
    def test_pack(self):
        self.assertEqual(hashlib_additional.be_pack(12345, 2), b"\x30\x39")

    def test_pad(self):
        self.assertEqual(hashlib_additional.be_pack(12345, 5), b"\x00\x00\x00\x30\x39")

    def test_overflow(self):
        with self.assertRaises(OverflowError):
            hashlib_additional.be_pack(12345, 1)
