"""Provider-neutral embedding job and vector DTOs (T12). Pydantic only.

An `EmbeddingJob` names the exact ordered texts to embed for one stable subject (for example a later index
generation). The server owns the model, dimensions and request shape; nothing here chooses them. Bounds are checked
before any tokenization, reservation or request:
- at most 10,000 inputs and 32 MiB of UTF-8 in total;
- each input 1-32,768 code points, at most 65,536 UTF-8 bytes, no NUL and no lone surrogate.

A vector is exactly 1536 finite floats (booleans, strings and NaN or infinity are refused, never coerced). Its values
are the float32 values the provider's numbers round to.
"""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import Field, StringConstraints, model_validator

from policyops_contracts.base import WireModel


INPUT_FORMAT: Literal["policyops.embed-input/v1"] = "policyops.embed-input/v1"
DIMENSIONS = 1536
MAX_JOB_INPUTS = 10_000
MAX_JOB_BYTES = 32 << 20
MAX_INPUT_BYTES = 65_536

Slug = Annotated[str, StringConstraints(pattern=r"^[a-z][a-z0-9_.-]{0,63}$")]
SubjectKey = Annotated[str, StringConstraints(min_length=1, max_length=200)]
EmbeddingInput = Annotated[str, StringConstraints(min_length=1, max_length=32_768)]
Digest = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
Component = Annotated[float, Field(strict=True, allow_inf_nan=False)]
Vector = Annotated[tuple[Component, ...], Field(min_length=DIMENSIONS, max_length=DIMENSIONS)]


class EmbeddingJob(WireModel):
    purpose: Slug
    subject_key: SubjectKey
    inputs: Annotated[tuple[EmbeddingInput, ...], Field(max_length=MAX_JOB_INPUTS)]
    input_format: Literal["policyops.embed-input/v1"] = INPUT_FORMAT

    @model_validator(mode="after")
    def _bounded_utf8(self) -> EmbeddingJob:
        total = 0
        for index, text in enumerate(self.inputs):
            if "\x00" in text:
                raise ValueError(f"input {index} contains NUL")
            try:
                size = len(text.encode("utf-8"))
            except UnicodeEncodeError:
                raise ValueError(f"input {index} is not valid UTF-8 text") from None
            if size > MAX_INPUT_BYTES:
                raise ValueError(f"input {index} is larger than {MAX_INPUT_BYTES} bytes")
            total += size
        if total > MAX_JOB_BYTES:
            raise ValueError("the job's inputs are larger than 32 MiB in total")
        return self


class EmbeddedInput(WireModel):
    position: Annotated[int, Field(ge=0, lt=MAX_JOB_INPUTS)]
    input_sha256: Digest
    vector: Vector
