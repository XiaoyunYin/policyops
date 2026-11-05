"""The server-owned embedding request contract (T12): one endpoint, one exact body shape, one config identity.

The endpoint identity is the OpenAI chat endpoint's (`contract.ENDPOINTS["openai"]`: host, auth header, no version
header), reused rather than duplicated; only the path differs. The body is exactly
`{"model", "input", "dimensions", "encoding_format": "float"}`:
- `encoding_format` is always explicit. Omitted, the installed SDK (`openai` 3.40.0) would request base64 and decode
  it after parsing; this code never uses that path and never calls the SDK's parser.
- `dimensions` and `model` come only from the server's `EmbeddingActor`; there is no `user` field and no SDK default.

`request_config_sha256` binds the endpoint, model, dimensions, encoding format, input format, contract version and
SDK version. It keys the embedding cache, so a vector is reused only for exactly the same request configuration.
"""

from __future__ import annotations

import hashlib
import json

from policyops.providers.contract import ENDPOINTS


EMBEDDING_CONTRACT_VERSION = "policyops.embedding-request/v1"
EMBEDDINGS_PATH = "/v1/embeddings"
ENCODING_FORMAT = "float"
INPUT_FORMAT = "policyops.embed-input/v1"
SDK = "openai==3.40.0"
ENDPOINT = ENDPOINTS["openai"]


def request_config_sha256(model: str, dimensions: int) -> str:
    body = {"v": EMBEDDING_CONTRACT_VERSION, "host": ENDPOINT.host, "path": EMBEDDINGS_PATH,
            "version_headers": dict(ENDPOINT.version_headers), "model": model, "dimensions": dimensions,
            "encoding_format": ENCODING_FORMAT, "input_format": INPUT_FORMAT, "sdk": SDK}
    return hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
