from __future__ import annotations

import math
import re


def shannon_entropy(data: bytes) -> float:
    """Return Shannon entropy in bits per byte for a byte sequence."""
    if not data:
        return 0.0

    histogram = [0] * 256
    for byte in data:
        histogram[byte] += 1

    total = len(data)
    entropy = 0.0
    for count in histogram:
        if count == 0:
            continue
        probability = count / total
        entropy -= probability * math.log2(probability)
    return entropy


def calculate_section_entropies(pe) -> list[float]:
    """Return entropy values for each PE section in order."""
    values: list[float] = []
    for section in pe.sections:
        section_data = section.get_data() or b""
        values.append(shannon_entropy(section_data))
    return values


def count_printable_strings(data: bytes, min_length: int = 4) -> int:
    """Count printable ASCII string fragments inside binary data."""
    if min_length <= 0:
        min_length = 4
    pattern = rb"[\x20-\x7E]{" + str(min_length).encode("ascii") + rb",}"
    return len(re.findall(pattern, data))
