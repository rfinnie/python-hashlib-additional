# SPDX-PackageName: python-hashlib-additional
# SPDX-PackageSupplier: Ryan Finnie <ryan@finnie.org>
# SPDX-PackageDownloadLocation: https://github.com/rfinnie/python-hashlib-additional
# SPDX-FileCopyrightText: © 2019 Ryan Finnie <ryan@finnie.org>
# SPDX-License-Identifier: MIT

import codecs
import copy
import random as _random
import zlib

__version__ = "1.2"


def be_pack(value, byte_len):
    """
    Pack an arbitrary numeric value into a big-endian byte sequence
    """

    out = bytearray()
    for i in range(byte_len):
        out.append(value & 0xFF)
        value = value >> 8
    if value > 0:
        raise OverflowError("Cannot fit value in byte_len")
    return bytes(reversed(out))


class HASH:
    """
    A hash represents the object used to calculate a checksum of a
    string of information.
    """

    name = "hash"
    digest_size = 0
    block_size = 1
    _checksum = 0

    def __init__(self, data=b"", **kwargs):
        self.update(data)

    def copy(self):
        """Return a copy of the hash object."""
        return copy.copy(self)

    def digest(self):
        """Return the digest value as a string of binary data."""
        return be_pack(self._checksum & (2 ** (self.digest_size * 8) - 1), self.digest_size)

    def hexdigest(self):
        """Return the digest value as a string of hexadecimal digits."""
        return codecs.encode(self.digest(), "hex_codec").decode("ascii")

    def update(self, data):
        """Update this hash object's state with the provided string."""
        pass


class crc32(HASH):
    name = "crc32"
    digest_size = 4

    def update(self, data):
        self._checksum = zlib.crc32(data, self._checksum)


class bsd(HASH):
    name = "bsd"
    digest_size = 2

    def update(self, data):
        for ch in data:
            self._checksum = (self._checksum >> 1) + ((self._checksum & 1) << 15)
            self._checksum += ch
            self._checksum &= 0xFFFF


class sysv(HASH):
    name = "sysv"
    digest_size = 2

    def update(self, data):
        for ch in data:
            self._checksum += ch
        self._checksum &= 0xFFFFFFFF

    def digest(self):
        r = (self._checksum & 0xFFFF) + ((self._checksum & 0xFFFFFFFF) >> 16)
        return be_pack((r & 0xFFFF) + (r >> 16), self.digest_size)


class twoping(HASH):
    """
    2ping checksum

    https://www.finnie.org/software/2ping/
    """

    name = "twoping"
    digest_size = 2
    block_size = 2
    _held_data = b""

    def update(self, data):
        data = self._held_data + data

        if (len(data) % 2) == 1:
            self._held_data = bytes([data[-1]])
            data = data[0:-1]
        else:
            self._held_data = b""

        for i in range(0, len(data), 2):
            self._checksum = self._checksum + (data[i] << 8) + data[i + 1]
            self._checksum = (self._checksum & 0xFFFF) + (self._checksum >> 16)

    def digest(self):
        checksum = self._checksum

        if self._held_data:
            checksum = checksum + (ord(self._held_data) << 8)
            checksum = (checksum & 0xFFFF) + (checksum >> 16)

        checksum = ~checksum & 0xFFFF

        if checksum == 0:
            checksum = 0xFFFF

        return be_pack(checksum, self.digest_size)


class udp(HASH):
    name = "udp"
    digest_size = 2
    block_size = 2
    _held_data = b""

    def _carry_around_add(self, a, b):
        c = a + b
        return (c & 0xFFFF) + (c >> 16)

    def update(self, data):
        data = self._held_data + data

        if (len(data) % 2) == 1:
            self._held_data = bytes([data[-1]])
            data = data[0:-1]
        else:
            self._held_data = b""

        for i in range(0, len(data), 2):
            self._checksum = self._carry_around_add(self._checksum, (data[i] + (data[i + 1] << 8)))

    def digest(self):
        checksum = self._checksum

        if self._held_data:
            checksum = self._carry_around_add(checksum, ord(self._held_data))

        if checksum == 0:
            checksum = 0xFFFF

        return be_pack(checksum, self.digest_size)


class adler32(HASH):
    name = "adler32"
    digest_size = 4
    _checksum = 1

    def update(self, data):
        self._checksum = zlib.adler32(data, self._checksum)


class cksum(HASH):
    name = "cksum"
    digest_size = 4
    _data_len = 0

    _table = (
        0x00000000,
        0x04C11DB7,
        0x09823B6E,
        0x0D4326D9,
        0x130476DC,
        0x17C56B6B,
        0x1A864DB2,
        0x1E475005,
        0x2608EDB8,
        0x22C9F00F,
        0x2F8AD6D6,
        0x2B4BCB61,
        0x350C9B64,
        0x31CD86D3,
        0x3C8EA00A,
        0x384FBDBD,
        0x4C11DB70,
        0x48D0C6C7,
        0x4593E01E,
        0x4152FDA9,
        0x5F15ADAC,
        0x5BD4B01B,
        0x569796C2,
        0x52568B75,
        0x6A1936C8,
        0x6ED82B7F,
        0x639B0DA6,
        0x675A1011,
        0x791D4014,
        0x7DDC5DA3,
        0x709F7B7A,
        0x745E66CD,
        0x9823B6E0,
        0x9CE2AB57,
        0x91A18D8E,
        0x95609039,
        0x8B27C03C,
        0x8FE6DD8B,
        0x82A5FB52,
        0x8664E6E5,
        0xBE2B5B58,
        0xBAEA46EF,
        0xB7A96036,
        0xB3687D81,
        0xAD2F2D84,
        0xA9EE3033,
        0xA4AD16EA,
        0xA06C0B5D,
        0xD4326D90,
        0xD0F37027,
        0xDDB056FE,
        0xD9714B49,
        0xC7361B4C,
        0xC3F706FB,
        0xCEB42022,
        0xCA753D95,
        0xF23A8028,
        0xF6FB9D9F,
        0xFBB8BB46,
        0xFF79A6F1,
        0xE13EF6F4,
        0xE5FFEB43,
        0xE8BCCD9A,
        0xEC7DD02D,
        0x34867077,
        0x30476DC0,
        0x3D044B19,
        0x39C556AE,
        0x278206AB,
        0x23431B1C,
        0x2E003DC5,
        0x2AC12072,
        0x128E9DCF,
        0x164F8078,
        0x1B0CA6A1,
        0x1FCDBB16,
        0x018AEB13,
        0x054BF6A4,
        0x0808D07D,
        0x0CC9CDCA,
        0x7897AB07,
        0x7C56B6B0,
        0x71159069,
        0x75D48DDE,
        0x6B93DDDB,
        0x6F52C06C,
        0x6211E6B5,
        0x66D0FB02,
        0x5E9F46BF,
        0x5A5E5B08,
        0x571D7DD1,
        0x53DC6066,
        0x4D9B3063,
        0x495A2DD4,
        0x44190B0D,
        0x40D816BA,
        0xACA5C697,
        0xA864DB20,
        0xA527FDF9,
        0xA1E6E04E,
        0xBFA1B04B,
        0xBB60ADFC,
        0xB6238B25,
        0xB2E29692,
        0x8AAD2B2F,
        0x8E6C3698,
        0x832F1041,
        0x87EE0DF6,
        0x99A95DF3,
        0x9D684044,
        0x902B669D,
        0x94EA7B2A,
        0xE0B41DE7,
        0xE4750050,
        0xE9362689,
        0xEDF73B3E,
        0xF3B06B3B,
        0xF771768C,
        0xFA325055,
        0xFEF34DE2,
        0xC6BCF05F,
        0xC27DEDE8,
        0xCF3ECB31,
        0xCBFFD686,
        0xD5B88683,
        0xD1799B34,
        0xDC3ABDED,
        0xD8FBA05A,
        0x690CE0EE,
        0x6DCDFD59,
        0x608EDB80,
        0x644FC637,
        0x7A089632,
        0x7EC98B85,
        0x738AAD5C,
        0x774BB0EB,
        0x4F040D56,
        0x4BC510E1,
        0x46863638,
        0x42472B8F,
        0x5C007B8A,
        0x58C1663D,
        0x558240E4,
        0x51435D53,
        0x251D3B9E,
        0x21DC2629,
        0x2C9F00F0,
        0x285E1D47,
        0x36194D42,
        0x32D850F5,
        0x3F9B762C,
        0x3B5A6B9B,
        0x0315D626,
        0x07D4CB91,
        0x0A97ED48,
        0x0E56F0FF,
        0x1011A0FA,
        0x14D0BD4D,
        0x19939B94,
        0x1D528623,
        0xF12F560E,
        0xF5EE4BB9,
        0xF8AD6D60,
        0xFC6C70D7,
        0xE22B20D2,
        0xE6EA3D65,
        0xEBA91BBC,
        0xEF68060B,
        0xD727BBB6,
        0xD3E6A601,
        0xDEA580D8,
        0xDA649D6F,
        0xC423CD6A,
        0xC0E2D0DD,
        0xCDA1F604,
        0xC960EBB3,
        0xBD3E8D7E,
        0xB9FF90C9,
        0xB4BCB610,
        0xB07DABA7,
        0xAE3AFBA2,
        0xAAFBE615,
        0xA7B8C0CC,
        0xA379DD7B,
        0x9B3660C6,
        0x9FF77D71,
        0x92B45BA8,
        0x9675461F,
        0x8832161A,
        0x8CF30BAD,
        0x81B02D74,
        0x857130C3,
        0x5D8A9099,
        0x594B8D2E,
        0x5408ABF7,
        0x50C9B640,
        0x4E8EE645,
        0x4A4FFBF2,
        0x470CDD2B,
        0x43CDC09C,
        0x7B827D21,
        0x7F436096,
        0x7200464F,
        0x76C15BF8,
        0x68860BFD,
        0x6C47164A,
        0x61043093,
        0x65C52D24,
        0x119B4BE9,
        0x155A565E,
        0x18197087,
        0x1CD86D30,
        0x029F3D35,
        0x065E2082,
        0x0B1D065B,
        0x0FDC1BEC,
        0x3793A651,
        0x3352BBE6,
        0x3E119D3F,
        0x3AD08088,
        0x2497D08D,
        0x2056CD3A,
        0x2D15EBE3,
        0x29D4F654,
        0xC5A92679,
        0xC1683BCE,
        0xCC2B1D17,
        0xC8EA00A0,
        0xD6AD50A5,
        0xD26C4D12,
        0xDF2F6BCB,
        0xDBEE767C,
        0xE3A1CBC1,
        0xE760D676,
        0xEA23F0AF,
        0xEEE2ED18,
        0xF0A5BD1D,
        0xF464A0AA,
        0xF9278673,
        0xFDE69BC4,
        0x89B8FD09,
        0x8D79E0BE,
        0x803AC667,
        0x84FBDBD0,
        0x9ABC8BD5,
        0x9E7D9662,
        0x933EB0BB,
        0x97FFAD0C,
        0xAFB010B1,
        0xAB710D06,
        0xA6322BDF,
        0xA2F33668,
        0xBCB4666D,
        0xB8757BDA,
        0xB5365D03,
        0xB1F740B4,
    )

    def update(self, data):
        for c in data:
            self._checksum = ((self._checksum << 8) & 0xFFFFFFFF) ^ self._table[(self._checksum >> 24) ^ c]
        self._data_len += len(data)

    def digest(self):
        checksum = self._checksum
        i = self._data_len
        while i:
            checksum = ((checksum << 8) & 0xFFFFFFFF) ^ self._table[(checksum >> 24) ^ (i & 0xFF)]
            i = i >> 8
        return be_pack(~checksum & 0xFFFFFFFF, self.digest_size)


class Fletcher(HASH):
    _held_data = b""
    digest_size = 2
    _checksum1 = 0
    _checksum2 = 0

    def update(self, data):
        data = self._held_data + data

        remainder_len = len(data) % self.block_size
        if remainder_len:
            self._held_data = data[0 - remainder_len :]
            data = data[0 : 0 - remainder_len]
        else:
            self._held_data = b""

        modulo = 2 ** (8 * self.block_size) - 1
        for i in range(0, len(data), self.block_size):
            c = 0
            for ic in range(self.block_size):
                c += data[i + ic] << (8 * ic)
            self._checksum1 = (self._checksum1 + c) % modulo
            self._checksum2 = (self._checksum2 + self._checksum1) % modulo

    def digest(self):
        if self._held_data:
            self.update(bytes(self.block_size - len(self._held_data)))

        assert self.digest_size in (2, 4, 8)
        assert self.digest_size == self.block_size * 2
        return be_pack(((self._checksum2 << (8 * self.block_size)) | self._checksum1), self.digest_size)


class fletcher16(Fletcher):
    name = "fletcher16"
    digest_size = 2


class fletcher32(Fletcher):
    name = "fletcher32"
    digest_size = 4
    block_size = 2


class fletcher64(Fletcher):
    name = "fletcher64"
    digest_size = 8
    block_size = 4


class sdbm(HASH):
    name = "sdbm"
    digest_size = 4

    def update(self, data):
        for ch in data:
            self._checksum = ((self._checksum << 16) + (self._checksum << 6) + ch - self._checksum) & 0xFFFFFFFF

    def digest(self):
        return be_pack(self._checksum, self.digest_size)


class djb2(HASH):
    name = "djb2"
    digest_size = 4
    _checksum = 5381

    def update(self, data):
        for ch in data:
            self._checksum = (((self._checksum << 5) + self._checksum) + ch) & 0xFFFFFFFF

    def digest(self):
        return be_pack(self._checksum, self.digest_size)


class _FNV(HASH):
    digest_size = 4
    block_size = 1
    version = "1a"
    _prime = 0
    _checksum = 0
    _params = {
        4: (2**24 + 2**8 + 0x93, 2166136261),
        8: (2**40 + 2**8 + 0xB3, 14695981039346656037),
        16: (2**88 + 2**8 + 0x3B, 144066263297769815596495629667062367629),
        32: (
            2**168 + 2**8 + 0x63,
            100029257958052580907070968620625704837092796014241193945225284501741471925557,
        ),
        64: (
            2**344 + 2**8 + 0x57,
            (
                9659
                + 303129496669498009435400716310 * 10**120
                + 466090418745672637896108374329 * 10**90
                + 434462657994582932197716438449 * 10**60
                + 813051892206539805784495328239 * 10**30
                + 340083876191928701583869517785
            ),
        ),
        128: (
            2**680 + 2**8 + 0x8D,
            (
                14197795064947621 * 10**270
                + 68722070641403218320880622795 * 10**240
                + 441933960878474914617582723252 * 10**210
                + 296732303717722150864096521202 * 10**180
                + 355549365628174669108571814760 * 10**150
                + 471015076148029755969804077320 * 10**120
                + 157692458563003215304957150157 * 10**90
                + 403644460363550505412711285966 * 10**60
                + 361610267868082893823963790439 * 10**30
                + 336411086884584107735010676915
            ),
        ),
    }

    def __init__(self, *args, digest_size=4):
        if digest_size not in self._params:
            raise ValueError("Invalid digest_size")
        self.digest_size = digest_size
        self._prime = self._params[self.digest_size][0]
        if self.version != "0":
            self._checksum = self._params[self.digest_size][1]
        super().__init__(*args)

    def update(self, data):
        for ch in data:
            if self.version == "1a":
                self._checksum = ((ch ^ self._checksum) * self._prime) & (2 ** (8 * self.digest_size) - 1)
            elif self.version in ("0", "1"):
                self._checksum = ((self._checksum * self._prime) & (2 ** (8 * self.digest_size) - 1)) ^ ch

    def digest(self):
        return be_pack(self._checksum, self.digest_size)


class fnv0(_FNV):
    name = "fnv0"
    version = "0"


class fnv1(_FNV):
    name = "fnv1"
    version = "1"


class fnv1a(_FNV):
    name = "fnv1a"
    version = "1a"


class random(HASH):
    """Dummy random hash"""

    name = "random"
    digest_size = 16

    def __init__(self, *args, digest_size=16):
        self.digest_size = digest_size
        super().__init__(*args)

    def update(self, data):
        if data or not self._checksum:
            self._checksum = _random.randint(0, 2 ** (self.digest_size * 8) - 1)


class null(HASH):
    """Dummy null hash"""

    name = "null"
    digest_size = 16

    def __init__(self, *args, digest_size=16):
        self.digest_size = digest_size
        super().__init__(*args)


__algorithm_map = {}
for obj in copy.copy(vars()).values():
    if type(obj) is type(HASH) and issubclass(obj, HASH) and obj.name != "hash":
        __algorithm_map[obj.name] = obj

# For the moment, everything can be done using stdlib,
# so available and guaranteed are the same.
algorithms_available = set(__algorithm_map.keys())
algorithms_guaranteed = algorithms_available

__all__ = tuple(set(list(algorithms_available) + ["new", "algorithms_available", "algorithms_guaranteed"]))


def new(name, *args, **kwargs):
    if name not in algorithms_available:
        raise ValueError("unsupported hash type " + name)
    return __algorithm_map[name](*args, **kwargs)
