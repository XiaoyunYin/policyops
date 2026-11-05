"""Deterministic Markdown sectioning and chunking for ingestion (T12): parser `policyops.md/v1`, chunk configuration
`chunk.cl100k-512-nooverlap/v1`.

The output is a pure function of the body, these versions and the token counter. Offsets are Python `str` indexes,
i.e. Unicode code points (sources refuse lone surrogates), and every chunk's text is exactly `body[start:end]`: CRLF,
tabs and other characters are never normalized.

**Lines.** `\\n` is the only line terminator; a `\\r` before it stays part of the line (and of the offsets) and is
treated as trailing whitespace when matching syntax. `str.splitlines` is deliberately not used: it would also split
on `\\x0b \\x0c \\x1c-\\x1e \\x85 \\u2028 \\u2029`.

**Fences** (a CommonMark subset): an opening line of at most three spaces of indent and three or more backticks or
tildes (a backtick fence's info string may not contain a backtick); a closing line of the same character, at least as
long, at most three spaces of indent and only spaces or tabs after it. An unclosed fence runs to the end of the body.
Headings inside a fence are text.

**Headings.** ATX only (setext headings, indented code and HTML blocks are text): at most three spaces of indent,
one to six `#`, then a space, a tab or the end of the line; the optional closing `#` sequence (after a space or tab)
and surrounding spaces and tabs are stripped. The heading path is the ancestor stack's non-empty texts joined with
` > `; a path over 500 code points is refused, never truncated.

**Sections.** A section is the text after one heading line up to the next heading line of any level (the preamble
has an empty path), so a parent never repeats its children's text. Heading-only and whitespace-only sections produce
no chunk.

**Units and packing.** A section is split into units: paragraphs (separated by blank lines: empty or only spaces,
tabs and `\\r`) and fenced blocks (one unit each, fences included); every unit is trimmed of whitespace
(`" \\t\\r\\n\\f\\v"`, explicitly, not `str.isspace`). Units are packed greedily, without overlap: a unit is appended
only if the exact submitted embedding input of the resulting span counts at most `MAX_TOKENS` and the span is at most
`MAX_CHUNK_CODE_POINTS`; packing stops at the first unit that would not fit. A chunk's text is the original slice
from its first unit's start to its last unit's end, blank lines between units included.

**Oversized units.** A paragraph that does not fit alone is split into sentences (`.`, `!` or `?` followed by
whitespace) which are packed the same way; a fenced block, or a sentence that does not fit alone, is hard split.

**Hard split** of a span starting at a non-whitespace position `p`: with `H = min(remaining, MAX_CHUNK_CODE_POINTS)`
and `P(k)` = "the right-trimmed `body[p:p+k]`, as a submitted input, is countable and counts at most `MAX_TOKENS`",
the selection is: refuse `hard_split_no_feasible_code_point` if `P(1)` is false; take `H` if `P(H)` is true;
otherwise bisect keeping `P(lo)` true and `P(hi)` false until `hi = lo + 1` and take `lo`. The selected candidate is
then counted once more (a separate final recheck). Prefix counts are **not** assumed monotone, so the result is a
feasible local boundary (the whole remainder, or `P(lo + 1)` false), not necessarily the largest feasible prefix, and
the refusal does not prove that no longer prefix fits. At most `HARD_SPLIT_MAX_COUNTS` counts per split; progress is
at least one code point.

Greedy packing makes the same promise: feasible and deterministic, not maximal.

**Counting.** The counter is the narrow `TokenCounter` protocol (production: the pinned cl100k `Tokenizer`). An
`InputRefused` from it (for example a regex piece over the per-piece byte bound) makes that candidate infeasible
rather than refusing the document, so a hard split can still separate it.

The submitted embedding input (`policyops.embed-input/v1`) is `heading path + "\\n\\n" + chunk text`, or the chunk
text alone when the path is empty.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
import math
import re
import time
from typing import Protocol

from policyops.providers.tokenizer import InputRefused


PARSER_VERSION = "policyops.md/v1"
CHUNK_CONFIG = "chunk.cl100k-512-nooverlap/v1"
EMBED_INPUT_FORMAT = "policyops.embed-input/v1"
MAX_TOKENS = 512
MAX_CHUNK_CODE_POINTS = 20_000  # chunks_text_length
MAX_HEADING_CODE_POINTS = 500  # chunks_heading_length
HARD_SPLIT_MAX_COUNTS = 2 + math.ceil(math.log2(MAX_CHUNK_CODE_POINTS - 1)) + 1  # endpoints, bisection, recheck
WHITESPACE = frozenset(" \t\r\n\f\v")

_FENCE_OPEN = re.compile(r"^ {0,3}(`{3,}|~{3,})(.*)$")
_FENCE_CLOSE = re.compile(r"^ {0,3}(`{3,}|~{3,})[ \t]*$")
_HEADING = re.compile(r"^ {0,3}(#{1,6})(?=[ \t]|$)(.*)$")


class TokenCounter(Protocol):
    def count(self, text: str) -> int: ...


class ParseRefused(ValueError):
    """The document cannot be chunked under this parser version; `offset` is a code-point position."""

    def __init__(self, code: str, offset: int = 0) -> None:
        super().__init__(f"{code} at {offset}")
        self.code, self.offset = code, offset


@dataclass(frozen=True)
class Chunk:
    start: int
    end: int
    text: str
    heading: str
    section_ordinal: int
    section_start: int
    section_end: int
    tokens: int  # the exact count of `embed_input(heading, text)`


@dataclass(frozen=True)
class _Line:
    start: int
    end: int  # excludes the "\n"
    content: str  # without a trailing "\r"


@dataclass(frozen=True)
class _Unit:
    start: int
    end: int
    fenced: bool


def embed_input(heading: str, text: str) -> str:
    return f"{heading}\n\n{text}" if heading else text


def _lines(body: str, start: int, end: int) -> list[_Line]:
    lines = []
    position = start
    while position < end:
        newline = body.find("\n", position, end)
        stop = end if newline < 0 else newline
        content = body[position:stop]
        lines.append(_Line(position, stop, content[:-1] if content.endswith("\r") else content))
        position = stop + 1 if newline >= 0 else end
    return lines


def _blank(line: _Line) -> bool:
    return all(char in " \t\r" for char in line.content)


def _opens(line: _Line) -> tuple[str, int] | None:
    match = _FENCE_OPEN.match(line.content)
    if match is None:
        return None
    fence = match.group(1)
    if fence[0] == "`" and "`" in match.group(2):
        return None
    return fence[0], len(fence)


def _closes(line: _Line, fence: tuple[str, int]) -> bool:
    match = _FENCE_CLOSE.match(line.content)
    return match is not None and match.group(1)[0] == fence[0] and len(match.group(1)) >= fence[1]


def _strip_closing(text: str) -> str:
    """Remove an ATX closing sequence (trailing `#`s preceded by a space or tab, or making up the whole text) with
    one backward cursor: linear in the line, unlike an unanchored regex."""
    end = len(text)
    while end > 0 and text[end - 1] == "#":
        end -= 1
    if end == len(text):
        return text
    if end == 0:
        return ""
    if text[end - 1] not in " \t":
        return text
    while end > 0 and text[end - 1] in " \t":
        end -= 1
    return text[:end]


def _heading(line: _Line) -> tuple[int, str] | None:
    """Level and text; `text` is already stripped of spaces and tabs at both ends (linear `str.strip`)."""
    match = _HEADING.match(line.content)
    if match is None:
        return None
    return len(match.group(1)), _strip_closing(match.group(2).strip(" \t"))


def _trim(body: str, start: int, end: int) -> tuple[int, int]:
    while start < end and body[start] in WHITESPACE:
        start += 1
    while end > start and body[end - 1] in WHITESPACE:
        end -= 1
    return start, end


@dataclass(frozen=True)
class _Section:
    ordinal: int
    heading: str
    start: int
    end: int


def sections(body: str) -> list[_Section]:
    """Heading-delimited sections (with their text ranges), the preamble first; fences hide headings."""
    found: list[_Section] = []
    stack: list[tuple[int, str]] = []
    heading, start = "", 0
    fence: tuple[str, int] | None = None
    for line in _lines(body, 0, len(body)):
        if fence is not None:
            if _closes(line, fence):
                fence = None
            continue
        opened = _opens(line)
        if opened is not None:
            fence = opened
            continue
        parsed = _heading(line)
        if parsed is None:
            continue
        found.append(_Section(len(found), heading, start, line.start))
        level, text = parsed
        while stack and stack[-1][0] >= level:
            stack.pop()
        stack.append((level, text))
        heading = " > ".join(t for _, t in stack if t)
        if len(heading) > MAX_HEADING_CODE_POINTS:
            raise ParseRefused("heading_path_too_long", line.start)
        start = min(line.end + 1, len(body))
    found.append(_Section(len(found), heading, start, len(body)))
    return found


def _units(body: str, start: int, end: int) -> list[_Unit]:
    units: list[_Unit] = []
    paragraph: list[_Line] = []

    def flush() -> None:
        if paragraph:
            s, e = _trim(body, paragraph[0].start, paragraph[-1].end)
            if s < e:
                units.append(_Unit(s, e, False))
            paragraph.clear()

    lines = _lines(body, start, end)
    index = 0
    while index < len(lines):
        line = lines[index]
        opened = _opens(line)
        if opened is not None:
            flush()
            last = index
            for probe in range(index + 1, len(lines)):
                last = probe
                if _closes(lines[probe], opened):
                    break
            s, e = _trim(body, line.start, lines[last].end)
            if s < e:
                units.append(_Unit(s, e, True))
            index = last + 1
            continue
        if _blank(line):
            flush()
        else:
            paragraph.append(line)
        index += 1
    flush()
    return units


def _sentences(body: str, start: int, end: int) -> list[_Unit]:
    units = []
    position = start
    index = start
    while index < end:
        if body[index] in ".!?" and index + 1 < end and body[index + 1] in WHITESPACE:
            s, e = _trim(body, position, index + 1)
            if s < e:
                units.append(_Unit(s, e, False))
            position = index + 1
        index += 1
    s, e = _trim(body, position, end)
    if s < e:
        units.append(_Unit(s, e, False))
    return units


class _Chunker:
    def __init__(self, body: str, counter: TokenCounter, deadline: float, clock: Callable[[], float]) -> None:
        self.body, self.counter, self.deadline, self.clock = body, counter, deadline, clock

    def count(self, heading: str, start: int, end: int) -> int | None:
        """The exact count of the submitted input for `body[start:end]`, or None if the counter refuses it."""
        try:
            return self.counter.count(embed_input(heading, self.body[start:end]))
        except InputRefused:
            return None

    def fits(self, heading: str, start: int, end: int) -> int | None:
        if end - start > MAX_CHUNK_CODE_POINTS:
            return None
        tokens = self.count(heading, start, end)
        return tokens if tokens is not None and tokens <= MAX_TOKENS else None

    def check_deadline(self, offset: int) -> None:
        if self.clock() >= self.deadline:
            raise ParseRefused("deadline_passed", offset)

    def pack(self, units: list[_Unit], heading: str, section: _Section, out: list[Chunk], *,
             split: Callable[[_Unit], None]) -> None:
        index = 0
        while index < len(units):
            self.check_deadline(units[index].start)
            start = units[index].start
            best: tuple[int, int] | None = None
            probe = index
            while probe < len(units):
                self.check_deadline(units[probe].start)
                tokens = self.fits(heading, start, units[probe].end)
                if tokens is None:
                    break
                best = (probe, tokens)
                probe += 1
            if best is None:
                split(units[index])
                index += 1
                continue
            last, tokens = best
            end = units[last].end
            out.append(Chunk(start, end, self.body[start:end], heading, section.ordinal, section.start, section.end,
                             tokens))
            index = last + 1

    def hard_split(self, start: int, end: int, heading: str, section: _Section, out: list[Chunk]) -> None:
        position, _ = _trim(self.body, start, end)
        while position < end:
            self.check_deadline(position)
            length, stop, tokens = self.select(position, end, heading)
            out.append(Chunk(position, stop, self.body[position:stop], heading, section.ordinal, section.start,
                             section.end, tokens))
            position, _ = _trim(self.body, position + length, end)

    def select(self, position: int, end: int, heading: str) -> tuple[int, int, int]:
        """The hard-split boundary at `position`: (code points consumed, chunk end, its exact count)."""
        limit = min(end - position, MAX_CHUNK_CODE_POINTS)

        def stop(k: int) -> int:
            return _trim(self.body, position, position + k)[1]

        def feasible(k: int) -> bool:
            return self.fits(heading, position, stop(k)) is not None

        if not feasible(1):
            raise ParseRefused("hard_split_no_feasible_code_point", position)
        if limit > 1 and feasible(limit):
            low = limit
        else:
            low, high = 1, limit
            while high - low > 1:
                middle = low + (high - low) // 2
                if feasible(middle):
                    low = middle
                else:
                    high = middle
        chosen = stop(low)
        tokens = self.fits(heading, position, chosen)  # the separate final recheck
        if tokens is None:
            raise ParseRefused("count_unstable", position)
        return low, chosen, tokens


def chunk_document(body: str, counter: TokenCounter, *, deadline: float,
                   clock: Callable[[], float] = time.monotonic) -> list[Chunk]:
    """All chunks of one rendered body, in document order, or a `ParseRefused`."""
    chunker = _Chunker(body, counter, deadline, clock)
    out: list[Chunk] = []
    for section in sections(body):
        chunker.check_deadline(section.start)
        units = _units(body, section.start, section.end)

        def split_sentence(unit: _Unit, section: _Section = section) -> None:
            chunker.hard_split(unit.start, unit.end, section.heading, section, out)

        def split_unit(unit: _Unit, section: _Section = section) -> None:
            if unit.fenced:
                chunker.hard_split(unit.start, unit.end, section.heading, section, out)
            else:
                chunker.pack(_sentences(body, unit.start, unit.end), section.heading, section, out,
                             split=split_sentence)

        chunker.pack(units, section.heading, section, out, split=split_unit)
    for chunk in out:
        if body[chunk.start:chunk.end] != chunk.text or not chunk.text:  # pragma: no cover - construction invariant
            raise ParseRefused("offset_invariant", chunk.start)
    return out
