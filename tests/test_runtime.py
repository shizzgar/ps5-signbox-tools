#!/usr/bin/env python3
"""Host regressions for the console access boundary and Orbit image selection."""
# SPDX-License-Identifier: MIT
import ctypes as C
import errno
from pathlib import Path
import shutil
import socket
import struct
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
READ = C.CFUNCTYPE(C.c_int, C.c_void_p, C.c_size_t, C.c_void_p, C.c_size_t)


class Region(C.Structure):
    _fields_ = [("start", C.c_size_t), ("end", C.c_size_t), ("protection", C.c_uint)]


def fixture(seed):
    """A PIE with an executable segment, one connect relocation and a writable GOT."""
    b = bytearray(0x3000)
    ident = b"\x7fELF\x02\x01\x01" + bytes(9)
    struct.pack_into("<16sHHIQQQIHHHHHH", b, 0, ident, 3, 62, 1, 64, 64, 0x2800,
                     0, 64, 56, 3, 64, 4, 0)
    programs = [(1, 7, 0x1000, 0, 0, 512, 512, 0x4000),
                (1, 6, 0x2000, 0x4000, 0, 0x400, 0x4000, 0x4000),
                (2, 6, 0x2200, 0x4200, 0, 64, 64, 8)]
    for i, p in enumerate(programs):
        struct.pack_into("<IIQQQQQQ", b, 64 + i * 56, *p)
    b[0x1000:0x1200] = bytes((i * 37 + seed) % 256 for i in range(512))
    sections = [(4, 0x4100, 0x2100, 24, 2, 24),
                (11, 0x4180, 0x2180, 48, 3, 24),
                (3, 0x41C0, 0x21C0, 9, 0, 1)]
    for i, (kind, address, offset, size, link, entsize) in enumerate(sections, 1):
        struct.pack_into("<IIQQQQIIQQ", b, 0x2800 + i * 64,
                         0, kind, 0, address, offset, size, link, 0, 8, entsize)
    struct.pack_into("<QQq", b, 0x2100, 0x4000, (1 << 32) | 6, 0)
    struct.pack_into("<IBBHQQ", b, 0x2198, 1, 0x12, 0, 0, 0, 0)
    b[0x21C0:0x21C9] = b"\0connect\0"
    for i, d in enumerate([(7, 0x4100), (8, 24), (9, 24), (0, 0)]):
        struct.pack_into("<qQ", b, 0x2200 + 16 * i, *d)
    return bytes(b)


class RuntimeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="ps5-runtime-test-")
        cls.work = Path(cls.temp.name)
        cls.cache = cls.work / "cached.elf"
        cls.mounts = cls.work / "sandbox"
        cls.mounts.mkdir()
        (cls.work / "orbit-connect.bin").write_bytes(bytes(0x4000))
        (cls.work / "report-stub.c").write_text(
            "void report_log(const char *format, ...) {(void)format;}\n"
            "void report_diag(const char *format, ...) {(void)format;}\n")
        subprocess.run(["cc", "-shared", "-fPIC", "-std=c11", "-D_DEFAULT_SOURCE",
                        "-Wall", "-Wextra", "-Werror", "-I", str(ROOT),
                        f'-DORBIT_RUNTIME="{cls.cache}"', f'-DORBIT_SANDBOX="{cls.mounts}"',
                        str(ROOT / "panel-access.c"), str(ROOT / "orbit-image.c"),
                        str(ROOT / "orbit-source.c"), str(cls.work / "report-stub.c"),
                        "-o", str(cls.work / "runtime.so")], cwd=cls.work, check=True)
        cls.lib = C.CDLL(str(cls.work / "runtime.so"), use_errno=True)
        cls.lib.panel_client_is_local.argtypes = [C.c_int]
        cls.lib.panel_request_is_trusted.argtypes = [C.c_int, C.c_char_p, C.c_char_p]
        cls.lib.orbit_find_runtime_import.argtypes = [C.POINTER(Region), C.c_size_t, READ,
                                                     C.c_void_p, C.POINTER(C.c_size_t), C.POINTER(C.c_size_t)]

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def setUp(self):
        self.cache.unlink(missing_ok=True)
        for path in self.mounts.iterdir():
            shutil.rmtree(path)

    def connection(self, address="127.0.0.1"):
        server = socket.socket()
        self.addCleanup(server.close)
        server.bind((address, 0))
        server.listen(1)
        client = socket.create_connection(server.getsockname())
        self.addCleanup(client.close)
        accepted, _ = server.accept()
        self.addCleanup(accepted.close)
        return accepted, ("%s:%s" % server.getsockname()).encode()

    def test_local_session_uses_actual_socket_peer(self):
        accepted, authority = self.connection()
        self.assertEqual(self.lib.panel_client_is_local(accepted.fileno()), 1)
        self.assertEqual(self.lib.panel_request_is_trusted(accepted.fileno(), authority, None), 1)
        self.assertEqual(self.lib.panel_request_is_trusted(
            accepted.fileno(), authority, b"http://" + authority), 1)

    def test_foreign_host_or_origin_is_rejected_even_on_loopback(self):
        accepted, authority = self.connection()
        for host, origin in [(b"localhost", None), (authority + b".evil.test", None),
                             (authority, b"https://" + authority),
                             (authority, b"http://evil.test"), (None, None)]:
            with self.subTest(host=host, origin=origin):
                self.assertEqual(self.lib.panel_request_is_trusted(accepted.fileno(), host, origin), 0)

    def test_lan_socket_is_not_local(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            probe.connect(("192.0.2.1", 9))  # Route lookup only; sends no datagrams.
            address = probe.getsockname()[0]
        if address.startswith("127."):
            self.skipTest("Host has no non-loopback IPv4 interface")
        accepted, authority = self.connection(address)
        self.assertEqual(self.lib.panel_client_is_local(accepted.fileno()), 0)
        self.assertEqual(self.lib.panel_request_is_trusted(accepted.fileno(), authority, None), 1)
        self.assertEqual(self.lib.panel_request_is_trusted(accepted.fileno(), b"127.0.0.1:8095", None), 0)

    def test_invalid_socket_does_not_authorize(self):
        self.assertEqual(self.lib.panel_client_is_local(-1), 0)
        self.assertEqual(self.lib.panel_request_is_trusted(-1, b"127.0.0.1:8095", None), 0)

    def bundle(self, data, instance="PPSA99177_000"):
        path = self.mounts / instance / "app0/orbit/orbit_store.elf"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return path

    def match(self, data, bases=(0x100000,)):
        regions = []
        for base in bases:
            regions += [Region(base, base + 0x4000, 7), Region(base + 0x4000, base + 0x8000, 3)]

        @READ
        def read(_, address, output, size):
            for base in bases:
                offset = address - base
                if 0 <= offset and offset + size <= 512:
                    C.memmove(output, data[0x1000 + offset:0x1000 + offset + size], size)
                    return 0
            return -1

        base, slot = C.c_size_t(), C.c_size_t()
        C.set_errno(0)
        result = self.lib.orbit_find_runtime_import((Region * len(regions))(*regions), len(regions),
                                                    read, None, C.byref(base), C.byref(slot))
        return result, C.get_errno(), base.value, slot.value

    def test_matching_cached_build(self):
        image = fixture(1)
        self.cache.write_bytes(image)
        self.assertEqual(self.match(image)[::2], (0, 0x100000))
        self.assertEqual(self.match(image)[3], 0x104000)

    def test_stale_cache_falls_back_to_matching_bundle(self):
        self.cache.write_bytes(fixture(1))
        image = fixture(2)
        self.bundle(image)
        self.assertEqual(self.match(image), (0, 0, 0x100000, 0x104000))

    def test_missing_cache_and_nonzero_mount_instance(self):
        image = fixture(3)
        self.bundle(image, "PPSA99177_004")
        self.assertEqual(self.match(image)[0], 0)

    def test_wrong_builds_fail_closed(self):
        self.cache.write_bytes(fixture(1))
        self.bundle(fixture(2))
        self.assertEqual(self.match(fixture(3))[:2], (-1, errno.ENOENT))

    def test_ambiguous_live_images_are_rejected(self):
        image = fixture(1)
        self.cache.write_bytes(image)
        self.assertEqual(self.match(image, (0x100000, 0x200000))[:2], (-1, errno.EEXIST))

    def test_malformed_or_symlink_cache_can_use_valid_bundle(self):
        image = fixture(4)
        bundle = self.bundle(image)
        self.cache.write_bytes(b"invalid ELF")
        self.assertEqual(self.match(image)[0], 0)
        self.cache.unlink()
        self.cache.symlink_to(bundle)
        self.assertEqual(self.match(image)[0], 0)

    def test_other_titles_and_invalid_instance_names_are_ignored(self):
        image = fixture(5)
        for name in ["OTHER_000", "PPSA99177_", "PPSA99177_000.old"]:
            self.bundle(image, name)
        self.assertEqual(self.match(image)[0], -1)


if __name__ == "__main__":
    unittest.main()
