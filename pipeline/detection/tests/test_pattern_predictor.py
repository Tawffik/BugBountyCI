import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..")))

from pipeline.detection.pattern_predictor import (
    _looks_like_id, _looks_like_word, _shape_of, in_scope, learn_grammar,
    predict, ID_PLACEHOLDER,
)


class TestScopeFilter(unittest.TestCase):
    def test_exact_and_subdomain_match(self):
        self.assertTrue(in_scope("https://superdrug.com/x", "superdrug.com"))
        self.assertTrue(in_scope("https://app.superdrug.com/x", "superdrug.com"))
        self.assertTrue(in_scope("https://www.superdrug.com:80/x", "superdrug.com"))

    def test_third_party_domain_excluded(self):
        # Real bug caught on the superdrug.com run: urls/all.txt mixed
        # in nhs.uk, sciencedirect.com, royalmail.com (linked/cited
        # pages) which are NOT the target's own application.
        self.assertFalse(in_scope("https://www.nhs.uk/conditions/x", "superdrug.com"))
        self.assertFalse(in_scope("https://personal.help.royalmail.com/x", "superdrug.com"))

    def test_no_target_domain_means_unfiltered(self):
        self.assertTrue(in_scope("https://anything.example.org/x", None))


class TestSegmentClassification(unittest.TestCase):
    def test_id_like_segments(self):
        self.assertTrue(_looks_like_id("1042"))
        self.assertTrue(_looks_like_id("a1b2c3d4e5f6"))  # hex hash
        self.assertTrue(_looks_like_id("550e8400-e29b-41d4-a716-446655440000"))  # uuid
        self.assertTrue(_looks_like_id("[customer_order_id]"))

    def test_word_segments_not_id(self):
        self.assertFalse(_looks_like_id("orders"))
        self.assertFalse(_looks_like_id("delivery"))
        self.assertFalse(_looks_like_id("edit_profile"))

    def test_junk_rejected_as_word(self):
        # long random cache-busting token: not a clean word, not a
        # classic id either — must not pollute the learned vocabulary
        self.assertFalse(_looks_like_word("841.89e5ee21c37ce544"))
        self.assertFalse(_looks_like_word("_next"))
        self.assertFalse(_looks_like_word("plp.min.js"))

    def test_real_word_accepted(self):
        self.assertTrue(_looks_like_word("orders"))
        self.assertTrue(_looks_like_word("invoice"))

    def test_all_caps_random_token_rejected(self):
        # real noise caught on superdrug.com: an analytics-beacon path
        # segment ("OHUXAQ") that happened to be pure a-z letters and
        # slipped past the plain word regex
        self.assertFalse(_looks_like_word("OHUXAQ"))
        self.assertFalse(_looks_like_word("NRXHW"))


class TestShapeExtraction(unittest.TestCase):
    def test_resource_id_action_shape(self):
        shape = _shape_of(["orders", "1042", "delivery"])
        self.assertEqual(shape, ("orders", ID_PLACEHOLDER, "delivery"))

    def test_multi_word_shape(self):
        shape = _shape_of(["profile", "dependant", "edit_profile", "add_avatar"])
        self.assertEqual(shape, ("profile", "dependant", "edit_profile", "add_avatar"))

    def test_all_id_path_rejected(self):
        # a path that's nothing but IDs teaches us no structure
        self.assertIsNone(_shape_of(["1042", "9981"]))


class TestGrammarLearningAndPrediction(unittest.TestCase):
    def setUp(self):
        # Deliberately mirrors real observed superdrug.com structure:
        # orders/{id}/delivery and profile/{id}/edit_profile exist, but
        # invoices/{id}/... and orders/{id}/edit_profile never appear —
        # a real predictor should suggest exactly those cross-overs.
        self.urls = [
            "https://app.example.com/orders/1042/delivery",
            "https://app.example.com/orders/9981/delivery",
            "https://app.example.com/profile/55/edit_profile",
            "https://app.example.com/invoices/701",
            "https://app.example.com/invoices/802",
            "https://app.example.com/info/contact",
            "https://app.example.com/_next/static/chunks/3kilv07.js",
            "https://app.example.com/img/logo.png",
        ]

    def test_learns_resource_action_relationship(self):
        grammar = learn_grammar(self.urls)
        self.assertIn("delivery", grammar["resource_actions"]["orders"])
        self.assertIn("edit_profile", grammar["resource_actions"]["profile"])

    def test_static_assets_excluded_from_grammar(self):
        grammar = learn_grammar(self.urls)
        all_words = set()
        for actions in grammar["resource_actions"].values():
            all_words |= actions
        self.assertNotIn("chunks", grammar["word_positions"])
        self.assertNotIn("img", grammar["word_positions"])

    def test_predicts_cross_resource_action_with_evidence(self):
        grammar = learn_grammar(self.urls)
        predictions = predict(grammar)
        paths = {p.path for p in predictions}
        # "invoices" has an id-bearing shape but no observed action yet;
        # "delivery" and "edit_profile" are actions seen on OTHER
        # resources — this is exactly the cross-pollination this module
        # exists to do.
        self.assertIn("/invoices/{id}/delivery", paths)
        self.assertIn("/invoices/{id}/edit_profile", paths)
        # every prediction must carry real evidence, not a bare guess
        for p in predictions:
            self.assertTrue(p.evidence.get("resource_seen_in"))
            self.assertTrue(p.evidence.get("action_seen_in"))

    def test_fuzz_path_has_real_id_substituted(self):
        # ffuf can't test a literal "{id}" token — every prediction for
        # a resource we've actually seen an id for must carry a
        # concrete, fetchable fuzz_path with a real id value from THIS
        # target substituted in, not the placeholder.
        grammar = learn_grammar(self.urls)
        predictions = predict(grammar)
        by_path = {p.path: p for p in predictions}
        pred = by_path["/invoices/{id}/delivery"]
        self.assertIn(pred.evidence["sample_id_used"], ("701", "802"))
        self.assertEqual(
            pred.evidence["fuzz_path"],
            f"invoices/{pred.evidence['sample_id_used']}/delivery",
        )
        self.assertNotIn("{id}", pred.evidence["fuzz_path"])

    def test_does_not_repredict_already_observed_combination(self):
        grammar = learn_grammar(self.urls)
        predictions = predict(grammar)
        paths = {p.path for p in predictions}
        # orders/{id}/delivery was already directly observed - predicting
        # it again would be noise, not a new lead
        self.assertNotIn("/orders/{id}/delivery", paths)

    def test_prediction_cap_respected(self):
        grammar = learn_grammar(self.urls)
        predictions = predict(grammar, max_predictions=1)
        self.assertLessEqual(len(predictions), 1)

    def test_empty_input_produces_no_predictions(self):
        grammar = learn_grammar([])
        predictions = predict(grammar)
        self.assertEqual(predictions, [])


class TestOnRealSuperdrugData(unittest.TestCase):
    """Same discipline as every other fix in this project: prove it on
    real captured data, not just synthetic fixtures."""

    FIXTURE = os.path.join(os.path.dirname(__file__), "fixtures", "real_superdrug_urls_sample.txt")

    def test_learns_and_predicts_from_real_run_sample(self):
        if not os.path.isfile(self.FIXTURE):
            self.skipTest("real fixture not present")
        with open(self.FIXTURE) as f:
            urls = [l.strip() for l in f if l.strip()]
        grammar = learn_grammar(urls, target_domain="superdrug.com")
        self.assertGreater(grammar["urls_scanned"], 0)
        predictions = predict(grammar)
        # Not asserting a specific count (real data varies) — just that
        # the pipeline runs end-to-end without crashing on messy real
        # URLs (query strings, encoded chars, mixed-depth paths) and
        # that every emitted prediction is still evidence-backed and
        # scoped to the actual target, not a third-party domain that
        # happened to be linked/cited in the crawl.
        for p in predictions:
            self.assertTrue(p.path.startswith("/"))
            self.assertIn("resource_seen_in", p.evidence)
            self.assertIn("action_seen_in", p.evidence)
            self.assertNotIn("royalmail", p.evidence["resource_seen_in"])
            self.assertNotIn("nhs.uk", p.evidence["resource_seen_in"])


if __name__ == "__main__":
    unittest.main()
