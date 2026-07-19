# `product_deadline(0)` contract analysis

Investigation date: 2026-07-19

This was a read-only investigation. No repair job ran, no agent was invoked,
the v2 baseline was not modified, and `/home/jeff/n8n` was not modified.

## Conclusion

The locally available implementation supports this contract:

> `product_deadline(0)` means immediate expiration.

It does not disable the deadline. It is not rejected by the context manager as
an invalid value. Negative values are also normalized to zero by the current
implementation, although the public watcher configuration rejects values
below 30 seconds.

In `csv-processor/app/ai/deadline.py`, the context manager:

1. converts the input to `float`;
2. clamps it with `max(0.0, ...)`;
3. stores `time.monotonic() + 0.0`; and
4. calls `require_time("product processing")` before `yield`.

`require_time()` raises `ProductDeadlineExceeded` whenever the remaining
budget is less than or equal to zero. Therefore the exception is raised while
entering `with product_deadline(0):`, before the context body executes.

The failed protected-baseline test catches the exception inside the body, so
its handler is never reached. The test, not the observed deadline behavior,
is inconsistent with the implementation.

## Evidence from call sites and configuration

The production call site is:

```text
csv-processor/app/ai/overnight.py:899
    with product_deadline(self.product_deadline_seconds):
```

`self.product_deadline_seconds` is initialized from the
`WATCHER_PRODUCT_DEADLINE_SECONDS` environment setting, with a positive
default. That constructor path can supply zero if the setting is explicitly
zero; it does not apply the later configuration-range validator during
initialization.

The operator configuration path uses `NewProductWatcher.apply_config()` and
declares the range `(float, 30, 840)` for
`product_deadline_seconds`. The dashboard/API and persisted watcher settings
flow through that validator, so those paths reject zero before assignment.
The UI also advertises a minimum of 30 seconds.

No literal `product_deadline(0)` production call was found. Existing deadline
tests use positive values (3, 5, 6, 7, and 9 seconds). The protected
regression test is the only local zero-value exercise found.

## Sanitized call-site inventory

| Location | Input source | Can supply zero? | Behavior |
|---|---|---:|---|
| `csv-processor/app/ai/overnight.py:899` | `self.product_deadline_seconds` | Yes through the constructor environment setting or direct in-process assignment; no literal zero found | Immediate `ProductDeadlineExceeded` on context entry |
| `csv-processor/app/ai/deadline.py:56` | Public `seconds` parameter | Yes | Zero and negative values normalize to an already-expired deadline |
| `csv-processor/tests/swarm_regressions/test_deadline_contract.py:14` | Literal zero in the regression test | Yes | Exception occurs during `with` entry, before the inner `try` |

The dashboard/API and persisted-settings path is not an additional zero-capable
runtime path after validation: `apply_config()` rejects values below 30.

## Existing documentation and history

The deadline module docstrings describe a “monotonic time budget,” say that
`ProductDeadlineExceeded` is raised when the product is exhausted, and say
that `require_time()` fails immediately when no budget remains. The context
manager docstring says it applies a budget; it does not describe zero as a
disable sentinel.

The local Git history shows the deadline module introduced with the same
`max(0.0, float(seconds))` and pre-`yield` `require_time()` behavior. No local
history documents zero as “disabled,” and no local history shows a special
invalid-zero exception policy.

## Proposed corrected baseline test

This is a proposal only; it was not applied during this investigation:

```python
import pytest

from app.ai.deadline import (
    ProductDeadlineExceeded,
    product_deadline,
    require_time,
    remaining_seconds,
)


def test_positive_deadline_allows_context_entry():
    with product_deadline(30):
        remaining = require_time("positive regression")
        assert remaining is not None
        assert 0 < remaining <= 30


def test_zero_deadline_expires_on_context_entry():
    with pytest.raises(ProductDeadlineExceeded, match="product processing"):
        with product_deadline(0):
            raise AssertionError("zero deadline unexpectedly entered its body")
```

The positive test separately proves successful context entry. The zero test
places `pytest.raises` around the entire context-manager statement, matching
the observed contract and preventing a false pass if the body were entered.

## Safety state

- Swarm mode: `DRY_RUN`.
- Deployment: `DISABLED`.
- Kill switch: `ENGAGED`.
- v2 baseline: unchanged.
- Original `/home/jeff/n8n`: inspected read-only; no Git or filesystem mutation.
- Codex/Gemini: not invoked.
