from __future__ import annotations

from unittest import TestCase, main, mock

import public_audit


class PublicAuditAdapterTests(TestCase):
    def test_clear_report_remains_success(self) -> None:
        with mock.patch("public_audit.audit.main", return_value=0):
            self.assertEqual(0, public_audit.main())

    def test_normal_blocking_report_is_deferred_to_risk_gate(self) -> None:
        with mock.patch("public_audit.audit.main", return_value=1):
            self.assertEqual(0, public_audit.main())

    def test_unexpected_exit_code_is_not_hidden(self) -> None:
        with mock.patch("public_audit.audit.main", return_value=2):
            self.assertEqual(2, public_audit.main())

    def test_missing_return_code_fails_closed(self) -> None:
        with mock.patch("public_audit.audit.main", return_value=None):
            self.assertEqual(2, public_audit.main())

    def test_boolean_return_code_fails_closed(self) -> None:
        with mock.patch("public_audit.audit.main", return_value=True):
            self.assertEqual(2, public_audit.main())

    def test_operational_exception_is_not_hidden(self) -> None:
        with mock.patch(
            "public_audit.audit.main",
            side_effect=RuntimeError("operational failure"),
        ):
            with self.assertRaisesRegex(RuntimeError, "operational failure"):
                public_audit.main()


if __name__ == "__main__":
    main()
