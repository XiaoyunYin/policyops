"""Parser `policyops.md/v1` and chunking `chunk.cl100k-512-nooverlap/v1` (T12): sections, fences, headings, exact
code-point slices, greedy packing, sentence and hard splits, the stated hard-split count bound, a non-monotone
counter counterexample, deadlines and linear handling of hostile heading lines. Offline only."""

from __future__ import annotations

import itertools
import time

import pytest

from policyops.providers import tokenizer as tk
from policyops.providers.tokenizer import InputRefused
from policyops.retrieval import parse
from policyops.retrieval.parse import HARD_SPLIT_MAX_COUNTS, MAX_TOKENS, ParseRefused, chunk_document, embed_input


class Length:
    """One token per code point of the submitted input: makes every bound exact and easy to reason about."""

    def __init__(self, factor: int = 1) -> None:
        self.factor, self.calls = factor, 0

    def count(self, text: str) -> int:
        self.calls += 1
        return len(text) * self.factor


class Feasible:
    """Counts by the submitted text's length through an explicit feasibility table (non-monotone on purpose)."""

    def __init__(self, feasible: set[int]) -> None:
        self.feasible = feasible

    def count(self, text: str) -> int:
        return 1 if len(text) in self.feasible else MAX_TOKENS + 1


def chunks(body: str, counter: object = None) -> list[parse.Chunk]:
    return chunk_document(body, counter or Length(), deadline=time.monotonic() + 30)  # type: ignore[arg-type]


def spans(body: str, counter: object = None) -> list[tuple[str, str]]:
    return [(c.heading, c.text) for c in chunks(body, counter)]


def test_sections_paths_preamble_and_heading_only_sections() -> None:
    body = "Intro line.\n# A\n## B\nText B.\n## C\n### D #\n\nText D.\n# E\n"
    assert spans(body) == [("", "Intro line."), ("A > B", "Text B."), ("A > C > D", "Text D.")]
    found = chunks(body)
    assert all(body[c.start:c.end] == c.text for c in found)
    assert [c.section_ordinal for c in found] == [0, 2, 4]  # A, C and E produce no chunk; ordinals still count


@pytest.mark.parametrize(("line", "heading"), [
    ("# Title", "Title"), ("#\tTabbed", "Tabbed"), ("   ### Indented", "Indented"), ("# Closed ##", "Closed"),
    ("# Closed ##   ", "Closed"), ("# Hash# kept", "Hash# kept"), ("# foo#", "foo#"), ("# #", ""), ("#", ""),
    ("# ###", ""), ("# x \\#", "x \\#"), ("####### seven", None), ("#5 not", None), ("    # code", None),
])
def test_atx_heading_recognition_and_closing_sequences(line: str, heading: str | None) -> None:
    body = f"{line}\nBody text."
    found = spans(body)
    if heading is None:
        assert found == [("", body.strip())]  # text, not a heading (units are trimmed of leading whitespace)
    else:
        assert found == [(heading, "Body text.")]


def test_fences_hide_headings_and_unclosed_fences_run_to_the_end() -> None:
    body = "# A\n```md\n# not a heading\n```\n# B\n~~~~\n# still code\n~~~\nmore\n"
    found = spans(body)
    assert found == [("A", "```md\n# not a heading\n```"), ("B", "~~~~\n# still code\n~~~\nmore")]
    # A backtick info string containing a backtick is not a fence, so the next heading is a heading.
    assert spans("# A\n``` x`y\n# B\ntext") == [("A", "``` x`y"), ("B", "text")]


def test_crlf_unicode_and_line_separators_are_preserved_exactly() -> None:
    body = "# Héading\r\n\r\nLine one\u2028still one \U0001f600\r\nline two\r\n\r\n\tTabbed para.\r\n"
    found = chunks(body)
    assert [(c.heading, c.text) for c in found] == [
        ("Héading", "Line one\u2028still one \U0001f600\r\nline two\r\n\r\n\tTabbed para.")]
    assert body[found[0].start:found[0].end] == found[0].text and found[0].start == body.index("Line one")


def test_whitespace_only_and_empty_sections_produce_no_chunk() -> None:
    assert spans("# A\n \t\r\n\f\n# B\n") == []
    assert spans("") == []


def test_greedy_packing_keeps_original_slices_and_never_overlaps() -> None:
    para = "word " * 40  # 200 code points
    body = "\n\n".join(para.strip() for _ in range(6))
    found = chunks(body)
    assert len(found) == 3 and all(len(embed_input("", c.text)) <= MAX_TOKENS for c in found)
    assert "\n\n" in found[0].text  # two paragraphs and the blank line between them, as in the body
    for first, second in itertools.pairwise(found):
        assert first.end <= second.start


def test_repeated_paragraphs_keep_distinct_positions() -> None:
    body = "# A\nSame text.\n# B\nSame text.\n"
    found = chunks(body)
    assert [c.text for c in found] == ["Same text.", "Same text."] and found[0].start != found[1].start


def test_an_oversized_paragraph_splits_at_sentences_then_hard_splits_a_long_sentence() -> None:
    sentence = "x" * 300 + "."
    body = f"{sentence} {sentence} {'y' * 1200}"
    found = chunks(body)
    assert [len(c.text) for c in found][:2] == [301, 301]
    assert all(len(c.text) <= MAX_TOKENS for c in found)
    assert "".join(c.text for c in found[2:]) == "y" * 1200  # hard split, contiguous, nothing lost


class Upto:
    """Feasible exactly for submitted inputs of at most `limit` code points (monotone); counts calls."""

    def __init__(self, limit: int) -> None:
        self.limit, self.calls = limit, 0

    def count(self, text: str) -> int:
        self.calls += 1
        return 1 if len(text) <= self.limit else MAX_TOKENS + 1


def test_hard_split_count_bound_including_the_final_recheck() -> None:
    chunker = parse._Chunker("a" * 25_000, Length(), time.monotonic() + 30, time.monotonic)
    assert chunker.select(0, 25_000, "") == (512, 512, 512)  # a monotone counter: the true maximum
    assert HARD_SPLIT_MAX_COUNTS == 18  # P(1), P(H), at most ceil(log2(19999)) = 15 bisections, the recheck
    worst = 0
    for limit in [*range(1, 20_000, 97), 19_998, 19_999, 20_000]:  # boundaries across the whole H = 20000 range
        bounded = Upto(limit)
        selected = parse._Chunker("a" * 25_000, bounded, time.monotonic() + 30, time.monotonic).select(0, 25_000, "")
        assert selected[1] == min(limit, 20_000)
        assert bounded.calls <= HARD_SPLIT_MAX_COUNTS
        worst = max(worst, bounded.calls)
    assert worst == HARD_SPLIT_MAX_COUNTS  # the stated bound is reached, not just respected


def test_a_non_monotone_counter_yields_a_feasible_local_boundary_not_the_maximum() -> None:
    feasible = {1, 2, 3, 7, 8, 9}
    found = chunks("a" * 20, Feasible(feasible))
    assert found[0].text == "aaa"  # bisection keeps P(lo) true and P(hi) false: lo = 3, P(4) false
    assert 4 not in feasible and max(feasible) == 9  # the documented limit: a longer prefix (9) also fits
    assert all(len(c.text) in feasible for c in found)


def test_the_refusal_is_named_and_bounded_even_when_a_longer_prefix_would_fit() -> None:
    with pytest.raises(ParseRefused) as caught:
        chunks("a" * 20, Feasible({5, 6}))
    assert caught.value.code == "hard_split_no_feasible_code_point" and caught.value.offset == 0


def test_a_heading_that_exhausts_the_budget_is_refused() -> None:
    with pytest.raises(ParseRefused, match="hard_split_no_feasible_code_point"):
        chunks("# " + "h" * 300 + "\nbody", Length(factor=2))


def test_heading_path_over_500_code_points_is_refused_not_truncated() -> None:
    with pytest.raises(ParseRefused, match="heading_path_too_long"):
        chunks("# " + "a" * 300 + "\n## " + "b" * 300 + "\ntext")


@pytest.mark.parametrize("spaces", [8192, 1_000_000])
def test_long_internal_heading_whitespace_is_linear(spaces: int) -> None:
    """Regression (draft finding: the unanchored closing-sequence regex was quadratic before any bound)."""
    started = time.monotonic()
    with pytest.raises(ParseRefused, match="heading_path_too_long"):
        chunks("# x" + " " * spaces + "y\nbody")
    found = chunks("# x" + " " * spaces + "###\nbody")
    assert [(c.heading, c.text) for c in found] == [("x", "body")]
    assert time.monotonic() - started < 2.0  # linear: milliseconds; the quadratic form took seconds at 65536


def test_the_deadline_is_checked_while_chunking() -> None:
    ticks = iter([0.0, 0.0, 0.0, 10.0, 10.0, 10.0, 10.0])
    with pytest.raises(ParseRefused, match="deadline_passed"):
        chunk_document("a\n\nb\n\nc\n\nd", Length(), deadline=5.0, clock=lambda: next(ticks))


class Refusing(Length):
    def count(self, text: str) -> int:
        if "#" * 20 in text:
            raise InputRefused("input_piece_too_long", 0)
        return super().count(text)


def test_a_counter_refusal_makes_a_candidate_infeasible_rather_than_refusing_the_document() -> None:
    body = "a" * 100 + "#" * 40 + "b" * 100
    found = chunks(body, Refusing())
    assert "".join(c.text for c in found) == body and all("#" * 20 not in c.text for c in found)


def test_chunking_is_deterministic() -> None:
    body = "# T\n" + "\n\n".join(f"Paragraph {i}. " + "z" * (i * 37 % 400) for i in range(40))
    assert chunks(body) == chunks(body)


def test_pinned_tokenizer_boundaries_at_512_and_513_tokens() -> None:
    tokenizer = tk.load()
    text = "a" + " a" * 511
    assert tokenizer.count(text) == 512
    one = chunk_document(text, tokenizer, deadline=time.monotonic() + 30)
    assert [c.text for c in one] == [text] and one[0].tokens == 512
    longer = text + " a"
    assert tokenizer.count(longer) == 513
    two = chunk_document(longer, tokenizer, deadline=time.monotonic() + 30)
    assert len(two) == 2 and all(c.tokens <= 512 for c in two)
    assert all(tokenizer.count(embed_input(c.heading, c.text)) == c.tokens for c in two)


def test_pinned_tokenizer_every_single_code_point_counts_at_least_one() -> None:
    tokenizer = tk.load()
    for char in ["a", "é", "東", "\U0001f600", "\u2028", "\t", "#", "\ufffd"]:
        assert tokenizer.count(char) >= 1
