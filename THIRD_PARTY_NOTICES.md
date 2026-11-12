# Third-party notices

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
its remaining uncertainty. Any image or artifact that later ships upstream files
(for example the planned retail simulator) must carry this notice.

Other Python and JavaScript dependencies are installed from the lock files under
their own licenses; their audit is not part of this notice.
