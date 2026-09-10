import io
import json
import unittest
from unittest import mock

import audit


class Response(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()
        return False


def component(
    *,
    ecosystem="npm",
    name="example",
    version="2.3.4",
    purl="pkg:npm/example@2.3.4",
):
    return audit.Component(
        ecosystem=ecosystem,
        name=name,
        version=version,
        purl=purl,
        scope="required",
        license="MIT",
        source_file="package-lock.json" if ecosystem == "npm" else "requirements.txt",
    )


class OsvEnrichmentTests(unittest.TestCase):
    def test_osv_query_hydrates_shallow_ids_and_deduplicates_detail_fetches(self):
        components = [component(), component(name="other", purl="pkg:npm/other@2.3.4")]
        detail_calls = []

        def fake_urlopen(request, timeout):
            if request.full_url.endswith("/v1/querybatch"):
                payload = json.loads(request.data.decode("utf-8"))
                self.assertEqual(2, len(payload["queries"]))
                return Response(
                    json.dumps(
                        {
                            "results": [
                                {"vulns": [{"id": "GHSA-test", "modified": "2026-09-10T00:00:00Z"}]},
                                {"vulns": [{"id": "GHSA-test", "modified": "2026-09-10T00:00:00Z"}]},
                            ]
                        }
                    ).encode("utf-8")
                )
            detail_calls.append((request.full_url, timeout))
            return Response(
                json.dumps(
                    {
                        "id": "GHSA-test",
                        "database_specific": {"severity": "HIGH"},
                        "affected": [],
                    }
                ).encode("utf-8")
            )

        with mock.patch("audit.urllib.request.urlopen", side_effect=fake_urlopen):
            results = audit.osv_query(components)

        self.assertEqual("HIGH", results[0]["vulns"][0]["database_specific"]["severity"])
        self.assertEqual("GHSA-test", results[1]["vulns"][0]["id"])
        self.assertEqual(1, len(detail_calls))
        self.assertTrue(detail_calls[0][0].endswith("/v1/vulns/GHSA-test"))
        self.assertEqual(30, detail_calls[0][1])

    def test_osv_query_follows_per_query_batch_pagination(self):
        item = component()
        batch_payloads = []

        def fake_urlopen(request, timeout):
            if request.full_url.endswith("/v1/querybatch"):
                payload = json.loads(request.data.decode("utf-8"))
                batch_payloads.append(payload)
                query = payload["queries"][0]
                if "page_token" not in query:
                    return Response(
                        b'{"results":[{"vulns":[{"id":"GHSA-one"}],"next_page_token":"page-2"}]}'
                    )
                self.assertEqual("page-2", query["page_token"])
                return Response(b'{"results":[{"vulns":[{"id":"GHSA-two"}]}]}')
            vulnerability_id = request.full_url.rsplit("/", 1)[-1]
            return Response(
                json.dumps({"id": vulnerability_id, "affected": []}).encode("utf-8")
            )

        with mock.patch("audit.urllib.request.urlopen", side_effect=fake_urlopen):
            results = audit.osv_query([item])

        self.assertEqual(["GHSA-one", "GHSA-two"], [entry["id"] for entry in results[0]["vulns"]])
        self.assertEqual(2, len(batch_payloads))

    def test_osv_query_rejects_mismatched_detail_record(self):
        def fake_urlopen(request, timeout):
            if request.full_url.endswith("/v1/querybatch"):
                return Response(b'{"results":[{"vulns":[{"id":"GHSA-requested"}]}]}')
            return Response(b'{"id":"GHSA-different","affected":[]}')

        with mock.patch("audit.urllib.request.urlopen", side_effect=fake_urlopen):
            with self.assertRaisesRegex(RuntimeError, "did not match GHSA-requested"):
                audit.osv_query([component()])

    def test_fixed_version_selects_range_containing_current_branch(self):
        item = component(
            name="brace-expansion",
            version="5.0.7",
            purl="pkg:npm/brace-expansion@5.0.7",
        )
        vulnerability = {
            "id": "GHSA-rgw5-rvv9-x895",
            "affected": [
                {
                    "package": {"ecosystem": "npm", "name": "brace-expansion"},
                    "ranges": [
                        {
                            "type": "SEMVER",
                            "events": [
                                {"introduced": "1.0.0"},
                                {"fixed": "1.1.18"},
                                {"introduced": "2.0.0"},
                                {"fixed": "2.1.4"},
                                {"introduced": "3.0.0"},
                                {"fixed": "3.0.6"},
                                {"introduced": "4.0.0"},
                                {"fixed": "5.0.9"},
                            ],
                        }
                    ],
                }
            ],
        }
        self.assertEqual("5.0.9", audit.fixed_version_of(vulnerability, item))

    def test_last_affected_range_does_not_invent_a_fixed_version(self):
        item = component(
            ecosystem="PyPI",
            name="chromadb",
            version="0.5.23",
            purl="pkg:pypi/chromadb@0.5.23",
        )
        vulnerability = {
            "id": "GHSA-2wm9-hf6c-p5cr",
            "affected": [
                {
                    "package": {"ecosystem": "PyPI", "name": "chromadb"},
                    "ranges": [
                        {
                            "type": "ECOSYSTEM",
                            "events": [
                                {"introduced": "0.4.17"},
                                {"last_affected": "1.5.9"},
                            ],
                        }
                    ],
                }
            ],
        }
        self.assertIsNone(audit.fixed_version_of(vulnerability, item))

    def test_vulnerabilities_for_uses_hydrated_severity_and_component_fix(self):
        item = component(
            name="sharp",
            version="0.35.2",
            purl="pkg:npm/sharp@0.35.2",
        )
        vulnerability = {
            "id": "GHSA-rgj7-g3m4-5g8c",
            "database_specific": {"severity": "HIGH"},
            "affected": [
                {
                    "package": {"ecosystem": "npm", "name": "sharp"},
                    "ranges": [
                        {
                            "type": "SEMVER",
                            "events": [
                                {"introduced": "0"},
                                {"fixed": "0.35.4"},
                            ],
                        }
                    ],
                }
            ],
        }
        findings = audit.vulnerabilities_for(
            "AtlasReaper311/example",
            [item],
            [{"vulns": [vulnerability]}],
        )
        self.assertEqual(1, len(findings))
        self.assertEqual("high", findings[0].severity)
        self.assertEqual("0.35.4", findings[0].fixed_version)


if __name__ == "__main__":
    unittest.main()
