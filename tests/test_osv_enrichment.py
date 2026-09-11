import io
import json
import unittest
import unittest.mock as mock

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
            url = request.full_url
            if url.endswith("/v1/querybatch"):
                return Response(
                    json.dumps(
                        {
                            "results": [
                                {"vulns": [{"id": "GHSA-test-1"}]},
                                {"vulns": [{"id": "GHSA-test-1"}]},
                            ]
                        }
                    ).encode("utf-8")
                )
            detail_calls.append(url)
            return Response(
                json.dumps(
                    {
                        "id": "GHSA-test-1",
                        "affected": [
                            {
                                "package": {"ecosystem": "npm", "name": "example"},
                                "ranges": [
                                    {
                                        "type": "SEMVER",
                                        "events": [
                                            {"introduced": "0"},
                                            {"fixed": "2.3.5"},
                                        ],
                                    }
                                ],
                            }
                        ],
                    }
                ).encode("utf-8")
            )

        with mock.patch("audit.urllib.request.urlopen", side_effect=fake_urlopen):
            results = audit.osv_query(components)

        self.assertEqual(2, len(results))
        self.assertEqual("GHSA-test-1", results[0]["vulns"][0]["id"])
        self.assertEqual("GHSA-test-1", results[1]["vulns"][0]["id"])
        self.assertEqual(1, len(detail_calls))

    def test_osv_batch_pagination_preserves_component_alignment(self):
        calls = []

        def fake_urlopen(request, timeout):
            if request.full_url.endswith("/v1/querybatch"):
                payload = json.loads(request.data.decode("utf-8"))
                calls.append(payload)
                query = payload["queries"][0]
                if query.get("page_token") == "next-1":
                    return Response(
                        b'{"results":[{"vulns":[{"id":"GHSA-page-2"}]}]}'
                    )
                return Response(
                    b'{"results":[{"vulns":[{"id":"GHSA-page-1"}],"next_page_token":"next-1"}]}'
                )
            vulnerability_id = request.full_url.rsplit("/", 1)[-1]
            return Response(
                json.dumps({"id": vulnerability_id, "affected": []}).encode("utf-8")
            )

        with mock.patch("audit.urllib.request.urlopen", side_effect=fake_urlopen):
            results = audit.osv_query([component()])

        self.assertEqual(
            ["GHSA-page-1", "GHSA-page-2"],
            [item["id"] for item in results[0]["vulns"]],
        )
        self.assertEqual("next-1", calls[1]["queries"][0]["page_token"])

    def test_osv_detail_id_mismatch_fails_closed(self):
        def fake_urlopen(request, timeout):
            if request.full_url.endswith("/v1/querybatch"):
                return Response(b'{"results":[{"vulns":[{"id":"GHSA-expected"}]}]}')
            return Response(b'{"id":"GHSA-wrong","affected":[]}')

        with mock.patch("audit.urllib.request.urlopen", side_effect=fake_urlopen):
            with self.assertRaisesRegex(RuntimeError, "did not match GHSA-expected"):
                audit.osv_query([component()])

    def test_fixed_version_selects_range_containing_current_version(self):
        vulnerability = {
            "id": "GHSA-test",
            "affected": [
                {
                    "package": {"ecosystem": "npm", "name": "example"},
                    "ranges": [
                        {
                            "type": "SEMVER",
                            "events": [
                                {"introduced": "1.0.0"},
                                {"fixed": "1.2.0"},
                                {"introduced": "2.0.0"},
                                {"fixed": "2.3.5"},
                            ],
                        }
                    ],
                }
            ],
        }
        self.assertEqual("2.3.5", audit.fixed_version_of(vulnerability, component()))

    def test_last_affected_range_has_no_published_fix(self):
        vulnerability = {
            "id": "GHSA-test",
            "affected": [
                {
                    "package": {"ecosystem": "PyPI", "name": "chromadb"},
                    "ranges": [
                        {
                            "type": "ECOSYSTEM",
                            "events": [
                                {"introduced": "0"},
                                {"last_affected": "1.5.9"},
                            ],
                        }
                    ],
                }
            ],
        }
        chroma = component(
            ecosystem="PyPI",
            name="chromadb",
            version="0.5.23",
            purl="pkg:pypi/chromadb@0.5.23",
        )
        self.assertIsNone(audit.fixed_version_of(vulnerability, chroma))

    def test_vulnerability_rows_receive_hydrated_severity_and_fix(self):
        components = [component()]
        results = [
            {
                "vulns": [
                    {
                        "id": "GHSA-test",
                        "severity": [
                            {
                                "type": "CVSS_V3",
                                "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                            }
                        ],
                        "affected": [
                            {
                                "package": {"ecosystem": "npm", "name": "example"},
                                "ranges": [
                                    {
                                        "type": "SEMVER",
                                        "events": [
                                            {"introduced": "0"},
                                            {"fixed": "2.3.5"},
                                        ],
                                    }
                                ],
                            }
                        ],
                    }
                ]
            }
        ]
        rows = audit.vulnerabilities_for("owner/repo", components, results)
        self.assertEqual(1, len(rows))
        self.assertEqual("critical", rows[0].severity)
        self.assertEqual("2.3.5", rows[0].fixed_version)


if __name__ == "__main__":
    unittest.main()
