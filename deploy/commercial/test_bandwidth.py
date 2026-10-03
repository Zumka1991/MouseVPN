import contextlib
import io
import math
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

import bandwidth


class BandwidthTest(unittest.TestCase):
    def test_uses_slower_direction_with_headroom_and_median(self):
        self.assertEqual(bandwidth.choose_limit([990, 1000, 1100], [500, 510, 520]), 459)
        self.assertEqual(bandwidth.choose_limit([100, 102, 98], [900, 910, 920]), 90)

    def test_invalid_or_unstable_measurements_never_become_a_budget(self):
        for values in [[1, 100, 100], [math.inf, 100, 100], [0, 100, 100], [100], [math.nan] * 3]:
            with self.assertRaises(ValueError):
                bandwidth.choose_limit(values, [100] * 3)
        with self.assertRaises(ValueError):
            bandwidth.choose_limit([100] * 3, [100] * 3, 1.1)

    def test_endpoint_cannot_include_credentials_or_use_plaintext(self):
        for url in ["http://example.com/down", "https://secret@example.com/down", "https://example.com/down?token=secret"]:
            with self.assertRaises(ValueError):
                bandwidth.endpoint(url)

    def test_partial_transfers_fail(self):
        with self.assertRaises(ValueError):
            bandwidth.sample(bandwidth.DOWNLOAD, False, size=100, transfer_fn=lambda *_: 99)

    def test_download_requires_success_uncompressed_bytes_and_a_complete_body(self):
        for status, encoding, chunks, valid in [
            (200, "identity", [b"hello"], True),
            (403, "identity", [b"hello"], False),
            (200, "gzip", [b"hello"], False),
            (200, "identity", [b"he", b""], False),
        ]:
            connection = MagicMock()
            response = connection.getresponse.return_value
            response.status = status
            response.getheader.return_value = encoding
            response.read.side_effect = chunks
            with self.subTest(status=status, encoding=encoding, chunks=chunks), patch.object(
                bandwidth.http.client, "HTTPSConnection", return_value=connection
            ):
                if valid:
                    self.assertEqual(bandwidth.transfer(bandwidth.DOWNLOAD, 5, False), 5)
                else:
                    with self.assertRaises(ValueError):
                        bandwidth.transfer(bandwidth.DOWNLOAD, 5, False)
                connection.close.assert_called_once()

    def test_failed_measurement_does_not_create_or_replace_configuration(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "traffic.toml"
            with patch("sys.argv", ["bandwidth.py", "--output", str(path)]), patch.object(bandwidth, "measure", side_effect=OSError("test failure")), contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit):
                    bandwidth.main()
            self.assertFalse(path.exists())
            path.write_text("original")
            with patch("sys.argv", ["bandwidth.py", "--output", str(path)]), patch.object(bandwidth, "measure") as measure, contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit):
                    bandwidth.main()
                measure.assert_not_called()
            self.assertEqual(path.read_text(), "original")


if __name__ == "__main__":
    unittest.main()
