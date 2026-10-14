"""Content normalization for duplicate comparisons only; evidence is never rewritten."""

import re
import unicodedata

from cyber_moe_datasets.models import Sample


def text(sample: Sample) -> str:
    # Compare prompts/evidence independently of the proposed answer.
    value = " ".join(m.content for m in sample.messages if m.role in {"user", "tool"})
    return " ".join(re.findall(r"\w+", unicodedata.normalize("NFKC", value).casefold()))


def shingles(sample: Sample, width: int = 5) -> set[str]:
    words = text(sample).split()
    if len(words) < width:
        return {" ".join(words)}
    return {" ".join(words[i : i + width]) for i in range(len(words) - width + 1)}
