"""Base class for data crossing a process or service boundary."""

from pydantic import BaseModel, ConfigDict


class WireModel(BaseModel):
    """Immutable, strictly typed message that rejects unknown fields.

    Strict mode refuses implicit coercion (for example "1" for an int), so a
    malformed peer message fails validation instead of changing meaning.
    """

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
