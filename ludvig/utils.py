from typing import Tuple


def get_line_number(content: str, position: int) -> Tuple[int, str]:
    lines = content.splitlines()
    lower = 0
    upper = len(lines) - 1
    while lower <= upper:
        index = int(lower + (upper - lower) / 2)
        start = content.index(lines[index])
        if position == start:
            return index, lines[index - 1]
        if start > position:
            upper = index - 1
        else:
            lower = index + 1

    return lower - 1, lines[lower - 1]
