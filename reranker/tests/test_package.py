"""Placeholder package smoke test, without loading model dependencies."""

import unittest

import policyops_reranker


class PackageTests(unittest.TestCase):
    def test_package_imports(self) -> None:
        self.assertEqual(policyops_reranker.__name__, "policyops_reranker")
