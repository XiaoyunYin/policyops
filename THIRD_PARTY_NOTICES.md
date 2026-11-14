# Third-party notices

PolicyOps is distributed under the [MIT license](LICENSE). Third-party components retain their own terms below.

## OpenTelemetry

The application installs `opentelemetry-sdk` 1.45.1, `opentelemetry-api` 1.45.1 and
`opentelemetry-semantic-conventions` 0.66b1 from the locked registry artifacts. Their installed distribution
metadata declares `License-Expression: Apache-2.0`; each distribution includes `licenses/LICENSE` containing
the Apache License, Version 2.0. No OpenTelemetry source is vendored here. Preserve these distribution license
files when redistributing an installed environment or image. The SDK is a direct dependency; the matching API
and semantic-conventions packages are dependencies of the SDK. No OTLP exporter or automatic instrumentation
package is added for Core telemetry.

## tiktoken and the cl100k_base vocabulary

The application counts embedding inputs locally with `tiktoken` 0.14.0 and its dependency `regex` 2026.9.29
(license metadata: Apache-2.0 AND CNRI-Python). Both libraries are installed from the locked registry artifacts, not
vendored.

`packages/policyops/src/policyops/providers/tokenizer.py` contains two values copied from tiktoken 0.14.0's
`tiktoken_ext/openai_public.py` (the `cl100k_base` definition): the regular-expression pattern string `PATTERN` and
the special-token ranks `SPECIAL_TOKENS`. They are pinned there so the application never calls tiktoken's
downloading factories. tiktoken's license:

```text
MIT License

Copyright (c) 2022 OpenAI, Shantanu Jain

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

The cl100k_base vocabulary file (`cl100k_base.tiktoken`, SHA-256
`223921b76ee99bde995b7ff738513eef100fb51d18c93597a113bcffe865b2a7`) is **not** included in this repository.
`scripts/fetch_tokenizer_vocab.py` downloads it for local use from the official URL that tiktoken itself uses and
checks that digest. tiktoken's MIT license covers its code; no separate license grant for the vocabulary file
itself was found, so this repository does not redistribute it and does not claim that the MIT license covers it.

## τ²-bench (tau2-bench)

PolicyOps's evaluator environment installs tau2-bench at commit
`19f13ea3f5fba8b4c4d272d1353590f29dc53062` from
<https://github.com/sierra-research/tau2-bench> as a dependency, and its
evaluator commands read that commit's public benchmark data from a local
acquisition outside this repository. No tau2-bench source file, task payload or
document text is committed here; `evals/manifests/` contains only task IDs,
counts and SHA-256 digests derived from it.

The repository's root `LICENSE` (SHA-256
`e67c5aa0074dfcaefd3c3a1aedb94cb539234aecd15d5a972574e3200e6252fe`, recorded in
`evals/manifests/tau2-19f13ea3/rights-audit.json`) reads:

```text
MIT License

Copyright (c) 2025 Sierra Research

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

This license is the only explicit grant found in the pinned repository. It does
not by itself establish the provenance of every data file; see
[docs/data-provenance.md](docs/data-provenance.md) for the per-file audit and
its remaining uncertainty. The retail simulator image ships the audited retail fixture and this license; any
redistributed image or artifact containing upstream files must retain this notice.

## Other installed dependencies: review before redistribution

### Compose image redistribution

The app/retail image definitions copy installed Python distributions with their `.dist-info` metadata,
license/notice texts and native libraries intact. Their frozen lock and this notice are shipped under
`/usr/share/policyops/` and `/opt/policyops/`. Python code remains readable; LGPL libraries are dynamically loaded
from the unmodified installed environment (they are not statically linked into PolicyOps). Rebuild from the
corresponding frozen lock to replace a library, observing its compatibility and license terms. Dependency sources
and releases are identified by those locks: <https://pypi.org/project/psycopg/>,
<https://pypi.org/project/psycopg-binary/>, <https://pypi.org/project/psycopg-pool/>,
<https://github.com/psycopg/psycopg>, <https://github.com/certifi/python-certifi>,
<https://github.com/ijl/orjson> and <https://github.com/tqdm/tqdm>.

The web runtime carries installed dependency package metadata and actual LICENSE/NOTICE/COPYING texts under
`/usr/share/policyops/web-notices/`, including attribution for bundled dependencies, plus its package lock.
Node/npm and development tooling stay in build stages. Caddy, CPython and PostgreSQL/Dex retain the notices
provided by their upstream base images; the exact image digests are recorded in `infra/images.json`.

The retail runtime additionally carries the unmodified, hash-verified tau2 retail `db.json` and MIT LICENSE under
`/opt/fixture/`, with the Sierra Research attribution above. It ships no benchmark task/reference/split data.
The full evaluator dependency set is retained as agreed, including litellm 1.82.6 with its documented advisory
limitations; its proxy and model clients are not started. Build-stage uv 0.13.7 is checksum-pinned and is absent
from final images (upstream: <https://github.com/astral-sh/uv>, MIT OR Apache-2.0).

These definitions preserve notices and reproducibility inputs; effective image contents, transitive native
library/source obligations and license inventory still require inspection before redistribution.
They do not claim complete legal clearance. Debian/Alpine base packages retain their upstream copyright/license
records; do not strip those files during image optimization.

The offline metadata inventory (`scripts/audit_licenses.py`, app environment and web lock) identifies
`psycopg` 3.3.6, `psycopg-binary` 3.3.6 and `psycopg-pool` 3.3.3 as LGPL-3.0-only;
`certifi` 2026.10.23 as MPL-2.0; `orjson` 3.13.0 as MPL-2.0 AND (Apache-2.0 OR MIT);
and the web build tool `lightningcss` 1.33.0 and its platform packages as MPL-2.0.
`caniuse-lite` 1.0.30001819 declares CC-BY-4.0. These are metadata observations, not a legal
clearance or a claim that every build dependency ships in the browser bundle.
The separately inventoried evaluator environment also declares `tqdm` 4.70.1 as MPL-2.0 AND MIT.

Preserve installed distribution license/notice files when redistributing environments or images.
Copyleft obligations, attribution, unknown/legacy declarations, transitive native libraries and the
exact files shipped need review for the actual images. The inventory deliberately returns a
review-required status for copyleft and unknown declarations; it does not waive them or replace
the evaluator's separate inventory and data-provenance audit. No complete legal clearance is claimed.
