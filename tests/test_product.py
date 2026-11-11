"""The device runner's own decisions, without a radio or a Pi."""
import importlib.util
import json
from pathlib import Path
import subprocess
import unittest
from unittest import mock

SPEC = importlib.util.spec_from_file_location("picast_product", Path(__file__).parents[1] / "tools/picast_product.py")
product = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(product)


def action(source, *records):
    lines = [json.dumps({"event": "awdl_action", "source": source})]
    lines += [json.dumps(r) for r in records]
    return lines


class Senders(unittest.TestCase):
    def test_iphone_before_mac_and_enough_frames(self):
        lines = []
        for _ in range(3):
            lines += action("aa:aa:aa:aa:aa:01", {"type": 21, "version_tag": {"device_class": product.CLASS_MAC}})
        for _ in range(3):
            lines += action("aa:aa:aa:aa:aa:02", {"type": 21, "version_tag": {"device_class": product.CLASS_IOS}},
                            {"channel_sequence": {"channels": [{"number": 6}, {"number": 149}]}})
        lines += action("aa:aa:aa:aa:aa:03", {"type": 21, "version_tag": {"device_class": product.CLASS_IOS}})
        lines.append('{"event":"summary","packets":7}')
        senders = product.heard_senders("\n".join(lines), own="aa:aa:aa:aa:aa:ff")
        self.assertEqual(senders["aa:aa:aa:aa:aa:02"][2], {6, 149})
        # The iPhone wins over the Mac; one heard only once is not a caller yet.
        self.assertEqual(product.choose_sender(senders, avoid=None), "aa:aa:aa:aa:aa:02")
        self.assertEqual(product.choose_sender(senders, avoid="aa:aa:aa:aa:aa:02"), "aa:aa:aa:aa:aa:01")

    def test_own_frames_and_noise_are_ignored(self):
        lines = action("aa:aa:aa:aa:aa:ff", {"type": 21, "version_tag": {"device_class": product.CLASS_IOS}})
        lines += ["not json", "[]"]
        self.assertEqual(product.heard_senders("\n".join(lines), own="aa:aa:aa:aa:aa:ff"), {})


class Radio(unittest.TestCase):
    def test_profile(self):
        self.assertTrue(product.radio_profile({6, 1}, None))       # its WLAN on 2.4 GHz
        self.assertFalse(product.radio_profile({6, 149}, True))    # only 5 GHz besides ours
        self.assertTrue(product.radio_profile({6}, None))
        self.assertFalse(product.radio_profile({6}, False))         # what we knew

    def test_stable_address_is_local_and_fixed(self):
        address = product.stable_address("e4:5f:01:00:00:01")
        self.assertEqual(address, "e6:5f:01:00:00:81")
        self.assertEqual(int(address[:2], 16) & 3, 2)              # locally administered, unicast


class Display(unittest.TestCase):
    def test_native_mode_from_edid(self):
        edid = bytearray(128)
        edid[:8] = bytes.fromhex("00ffffffffffff00")
        # 2560x1080, 185.58 MHz
        edid[54:72] = bytes([0x7e, 0x48, 0x00, 0xa0, 0xa0, 0x38, 0x1f, 0x40]) + bytes(10)
        self.assertEqual(product.edid_native(bytes(edid)), {"width": 2560, "height": 1080, "pixel_clock_mhz": 185.58})
        self.assertIsNone(product.edid_native(b"\x00" * 128))


class Settings(unittest.TestCase):
    def config(self, stdout, returncode=0):
        result = subprocess.CompletedProcess([], returncode, stdout=stdout, stderr="")
        with mock.patch.object(product, "picast", return_value=result):
            return product.settings()

    def test_values_from_the_receiver(self):
        values = self.config('{"name":"Beamer","language":"de","delay_ms":320,"maintenance":true,"warnings":[]}\n')
        self.assertEqual((values["name"], values["language"], values["delay_ms"], values["maintenance"]),
                         ("Beamer", "de", 320, True))

    def test_defaults_when_unreadable(self):
        for broken in ("", "nonsense", "[1]"):
            values = self.config(broken)
            self.assertEqual((values["name"], values["delay_ms"], values["maintenance"]), ("PiCast", 270, False))

    def test_session_environment(self):
        config = {"name": "Küche", "delay_ms": 300}
        env = product.session_environment(config, shares_band=True, size="2560x1080")
        self.assertEqual((env["PICAST_NAME"], env["PICAST_PLAYOUT_DELAY_MS"], env["PICAST_AWDL_PROFILE"],
                          env["PICAST_SCREEN"]), ("Küche", "300", "gaps1", "2560x1080"))
        env = product.session_environment(config, shares_band=False, size=None)
        self.assertEqual(env["PICAST_AWDL_PROFILE"], "full")
        self.assertNotIn("PICAST_SCREEN", env)


if __name__ == "__main__":
    unittest.main()
