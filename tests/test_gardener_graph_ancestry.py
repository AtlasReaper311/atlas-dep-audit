from __future__ import annotations

import unittest

import gardener_graph_candidates as graph


class GardenerGraphAncestryTests(unittest.TestCase):
    def test_root_dev_dependency_is_a_direct_ancestor(self) -> None:
        packages = {
            "": {"devDependencies": {"wrangler": "^4.127.0"}},
            "node_modules/wrangler": {
                "version": "4.127.0",
                "dependencies": {"miniflare": "^5.0.0"},
            },
            "node_modules/miniflare": {
                "version": "5.0.0",
                "dependencies": {"sharp": "0.35.2"},
            },
            "node_modules/sharp": {"version": "0.35.2"},
        }
        self.assertEqual(
            {"wrangler"},
            graph.direct_ancestors(packages, "node_modules/sharp"),
        )

    def test_comparator_ranges_do_not_double_apply_operators(self) -> None:
        self.assertTrue(graph.spec_accepts(">=1.0.0 <2.0.0", (1, 5, 0)))
        self.assertFalse(graph.spec_accepts(">=1.0.0 <2.0.0", (2, 0, 0)))


if __name__ == "__main__":
    unittest.main()
