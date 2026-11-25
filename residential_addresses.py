"""Local, component-based recognition of residential address spans in English text."""
import re

# Match at the current position only. Names may vary, but connectors, verbs and
# field labels cannot form part of a name. Keep horizontal space distinct from lines.
SPACE = r"[ \t\u00a0]+"
STOP_WORDS = (r"i|we|you|my|your|our|the|and|but|for|on|in|at|near|from|is|are|was|will|can|please|"
        r"thank|thanks|send|call|email|phone|mobile|password|address|meet|tomorrow|today|"
        r"said|says|after|before|works?|lives?|then|that|which|where|with|when|has|have|"
        r"looks?|opens?|closes?|needs?|remains?|moved|visited|see|regards|hello|deliver|ship|to")
WORD = rf"(?!(?:{STOP_WORDS})\b)[^\W\d_][^\W\d_]*(?:[-’'][^\W\d_]+)*"
NAME = rf"{WORD}(?:{SPACE}{WORD}){{0,3}}?"
HOUSE_NUMBER = r"(?:[a-z]-?)?\d{1,6}(?:[-/]\w{1,6}){0,3}[a-z]?"
STREET = r"(?:street|road|avenue|lane|drive|boulevard|court|way|terrace|square|circle|st|rd|ave|ln|dr|blvd|ct)"
BUILDING = r"(?:apartments?|residency|residences?|estate|enclave|heights|gardens|towers|villas|society|community)"
LOCALITY = r"(?:colony|nagar|village|district|layout|sector)"
UNIT = r"(?:flat|apartment|apt|unit|plot|house|suite|h\.?[ \t]*no\.?)"
NUMBER_PREFIX = r"(?:[ \t]+(?:no\.?|number))?[ \t]*(?:#[ \t]*)?"
POSTCODE = r"(?:[a-z]{1,2}\d[\da-z]?[ \t]+\d[a-z]{2}|[a-z]\d[a-z][ \t]?\d[a-z]\d|\d{5}-\d{4}|\d{5,6})"
ADDRESS_LABEL = re.compile(r"\b(?:home |mailing |residential |shipping )?address\s*(?:is\b|[:=])\s*", re.I)
RESIDENTIAL_CONTEXT = re.compile(r"\b(?:live|lives|reside|resides|my home is|ship to|deliver to)(?: (?:in|at))?\s*$", re.I)
SEPARATOR = re.compile(r"[ \t\u00a0]*(?:,[ \t\u00a0]*(?:\r?\n[ \t]*)?|\r?\n[ \t]*|[ \t\u00a0]+)")
CONNECTOR = re.compile(r"(at|near|opposite|beside|in)\b[ \t]+", re.I)

# The same component grammar is used to find a start and extend it. Captured
# offsets index the original draft, including commas and line breaks.
PATTERNS = {
    "unit": rf"{UNIT}{NUMBER_PREFIX}{HOUSE_NUMBER}",
    "block": rf"(?:block|tower|sector){SPACE}(?:{HOUSE_NUMBER}|[a-z])",
    "street": rf"{HOUSE_NUMBER}{SPACE}{NAME}{SPACE}{STREET}",
    "road": rf"(?:road|lane|street){NUMBER_PREFIX}{HOUSE_NUMBER}|{NAME}{SPACE}{STREET}",
    "building": rf"{NAME}{SPACE}{BUILDING}",
    "locality": rf"{NAME}{SPACE}{LOCALITY}|(?:village|district){SPACE}{NAME}(?=[ \t]*(?:[,.;\n]|$))",
    "box": r"P\.?[ \t]*O\.?[ \t]+Box[ \t]+\d{1,10}",
    "post": POSTCODE,
}


def components(kinds):
    return re.compile(r"\b(?:" + "|".join(f"(?P<{k}>{PATTERNS[k]})" for k in kinds) + r")(?![\w/-])", re.I)


ANCHOR = components(("unit", "block", "street", "box", "building", "locality"))
COMPONENT = components(("unit", "block", "street", "building", "road", "locality", "box", "post"))
# Bare locality names are accepted only in an address already in progress.
# Limit them to a whole delimited field or an explicitly linked place in prose.
PLACE = re.compile(rf"(?:{NAME}|(?-i:[A-Z]{{2}}))(?={SPACE}(?:{POSTCODE}|and|but|for|where|before|after)\b|[ \t]*(?:[,.;!?\r\n]|$))", re.I)
LANDMARK = re.compile(rf"{NAME}{SPACE}(?:park|school|station|market|temple|hospital|mall|bridge|gate)\b", re.I)
PLACE_BEFORE_POST = re.compile(rf"{NAME}(?={SPACE}{POSTCODE}\b)", re.I)


def address_spans(text):
    last_end = 0
    for anchor in ANCHOR.finditer(text):
        start, end = anchor.span()
        if start < last_end:
            continue
        prefix = text[max(0, start - 80):start]
        labelled = any(m.end() == len(prefix) for m in ADDRESS_LABEL.finditer(prefix))
        residential = labelled or bool(RESIDENTIAL_CONTEXT.search(prefix))
        kinds = {anchor.lastgroup}
        component_count = 1
        for _ in range(12):
            sep = SEPARATOR.match(text, end)
            if not sep:
                break
            pos = sep.end()
            if ADDRESS_LABEL.match(text, pos):
                break
            connector = CONNECTOR.match(text, pos)
            if connector:
                pos = connector.end()
            part = COMPONENT.match(text, pos)
            if part:
                kind = part.lastgroup
                # Two consecutive residences should be individually selectable.
                if kind in kinds and kind in {"unit", "street", "box"}:
                    break
            elif connector and connector[1].lower() in {"near", "opposite", "beside"}:
                part = LANDMARK.match(text, pos)
                kind = "landmark"
            elif connector or "," in sep[0] or "\n" in sep[0]:
                part = PLACE.match(text, pos)
                kind = "place"
                if part and "\n" in sep[0] and "," not in sep[0]:
                    # Keep a following standalone text line outside the span.
                    if not re.match(rf"[ \t]*(?:,|{POSTCODE}\b)", text[part.end():], re.I):
                        break
            else:
                # Without commas or a linking word, a postal code supplies a
                # boundary for a plain city/state phrase following the locator.
                part = PLACE_BEFORE_POST.match(text, pos)
                kind = "place"
            if not part:
                break
            end = part.end()
            kinds.add(kind)
            component_count += 1
            if kind == "post":
                break
        if (anchor.lastgroup in {"building", "locality"} and not residential
                and not kinds.intersection({"unit", "street", "block", "box"})):
            continue
        specific = len(kinds) >= 2 or (
            residential and (anchor.lastgroup in {"street", "box"} or component_count >= 2)
        )
        if not residential and kinds <= {"block", "place", "post"}:
            specific = False  # A city sector can describe an entire public area.
        last_end = end
        yield start, end, "high" if specific else "review"
