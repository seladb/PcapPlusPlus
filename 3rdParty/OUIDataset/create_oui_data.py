import argparse
from dataclasses import dataclass, asdict, is_dataclass
import json
import re
from typing import Optional
import urllib.request

MANUF_URL = "https://gitlab.com/wireshark/wireshark/-/raw/master/epan/manuf-data.c"
REGEX_PATTERN = r"\{\s*((?:0x[0-9A-Fa-f]{2}\s*,\s*){2}(?:0x[0-9A-Fa-f]{2}\s*,\s*)*0x[0-9A-Fa-f]{2})\s*\},\s*(\"(?:[^\"\\]|\\.)*\"),\s*(\"(?:[^\"\\]|\\.)*\")"


@dataclass
class LineElements:
    mac_short: str
    vendor: str
    mac_long: Optional[str] = None
    mac_mask: Optional[int] = None


@dataclass
class MaskedFilter:
    mask: int
    vendors: dict[str, str]


@dataclass
class OUIRecord:
    vendor: str
    masked_filters: Optional[list[MaskedFilter]] = None


class EnhancedJSONEncoder(json.JSONEncoder):
    @staticmethod
    def to_camel_case(snake_case_str):
        first, *others = snake_case_str.split("_")
        return "".join([first.lower(), *map(str.title, others)])

    def default(self, o):
        if is_dataclass(o):
            return asdict(
                o,
                dict_factory=lambda x: {
                    self.to_camel_case(k): v for (k, v) in x if v is not None
                },
            )
        return super().default(o)


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input-file", "-i", type=str, help="Input file path")
    parser.add_argument(
        "--output-file",
        "-o",
        type=str,
        default="PCPP_OUIDataset.json",
        help="Output file path",
    )
    return parser.parse_args()


def convert_line(line: str) -> list[str]:
    match_result = re.findall(REGEX_PATTERN, line)

    if len(match_result) < 1 or len(match_result[0]) < 3:
        return None

    return (
        "".join(
            format(int(s.strip(), 16), "02x") for s in match_result[0][0].split(",")
        ),
        match_result[0][1][1 : len(match_result[0][1]) - 1].replace("\\", ""),
        match_result[0][2][1 : len(match_result[0][2]) - 1].replace("\\", ""),
    )


def parse_mac_and_vendor(line_parts: list[str]) -> Optional[LineElements]:
    if line_parts is None or len(line_parts) < 3:
        return None

    if len(line_parts[0]) == 6:
        mac_short = line_parts[0].lower().strip()
        vendor = line_parts[2].strip()
        return LineElements(mac_short=mac_short, vendor=vendor)
    elif 6 < len(line_parts[0]) < 11:
        mac_short = line_parts[0][:6].lower().strip()
        mac_long = format(line_parts[0].lower().strip(), "0<12")
        mac_mask = 28 if (len(line_parts[0]) == 8) else 36
        vendor = line_parts[2].strip()
        return LineElements(
            mac_short=mac_short, vendor=vendor, mac_long=mac_long, mac_mask=mac_mask
        )

    return None


def find_mask_in_masked_filters(
    masked_filters: list[MaskedFilter], mask: int
) -> Optional[MaskedFilter]:
    for masked_filter in masked_filters:
        if masked_filter.mask == mask:
            return masked_filter

    return None


def create_masked_filter(mask: int, mac_long_hash: str, vendor: str) -> MaskedFilter:
    return MaskedFilter(mask=mask, vendors={mac_long_hash: vendor})


def update_masked_filters_in_record(
    oui_record: OUIRecord, line_elements: LineElements
) -> None:
    mac_long_hash = int(line_elements.mac_long.replace(":", ""), 16)

    if not oui_record.masked_filters:
        oui_record.masked_filters = []

    if masked_filter := find_mask_in_masked_filters(
        oui_record.masked_filters, line_elements.mac_mask
    ):
        masked_filter.vendors[str(mac_long_hash)] = line_elements.vendor
    else:
        masked_filter = create_masked_filter(
            line_elements.mac_mask, str(mac_long_hash), line_elements.vendor
        )
        oui_record.masked_filters.append(masked_filter)


def update_oui_dataset(
    oui_dataset: dict[str, OUIRecord], line_elements: LineElements
) -> None:
    mac_hash = str(int(line_elements.mac_short.replace(":", ""), 16))

    if mac_hash not in oui_dataset:
        oui_dataset[mac_hash] = OUIRecord(
            vendor=line_elements.vendor if not line_elements.mac_long else ""
        )

    if line_elements.mac_long and line_elements.mac_mask:
        update_masked_filters_in_record(oui_dataset[mac_hash], line_elements)


def main() -> None:
    args = parse_args()

    if args.input_file:
        with open(args.input_file, "r", encoding="utf8") as in_file:
            lines = in_file.readlines()
    else:
        with urllib.request.urlopen(MANUF_URL) as in_file:
            lines = in_file.readlines()

    oui_dataset = {}

    for line in lines:
        if isinstance(line, bytes):
            line = line.decode("utf-8")

        if line.startswith(("//", "/*", " *", "*/", "\n", "\r\n", "static", "};")):
            continue

        if line_elements := parse_mac_and_vendor(convert_line(line)):
            update_oui_dataset(oui_dataset, line_elements)

    with open(args.output_file, "w", encoding="utf8") as out_file:
        json.dump(
            oui_dataset,
            out_file,
            indent=4,
            separators=(",", ": "),
            ensure_ascii=False,
            cls=EnhancedJSONEncoder,
        )
        out_file.write("\n")


if __name__ == "__main__":
    main()
