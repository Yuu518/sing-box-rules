#!/usr/bin/env python3

import argparse

def remove_domains(file_to_remove, file_to_remove_from, output_file):
    with open(file_to_remove, "r") as f_remove, open(
        file_to_remove_from, "r"
    ) as f_from:
        domains_to_remove = set(line.strip() for line in f_remove if line.strip() and not line.strip().startswith("#"))
        all_domains = set(line.strip() for line in f_from if line.strip() and not line.strip().startswith("#"))

    remaining_domains = all_domains - domains_to_remove

    with open(output_file, "w") as output:
        output.write("\n".join(sorted(remaining_domains)))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Remove domains from a file.")
    parser.add_argument(
        "-remove", required=True, help="File containing domains to be removed"
    )
    parser.add_argument(
        "-from", required=True, dest="from_file", help="File to remove domains from"
    )
    parser.add_argument("-out", required=True, help="Output file")

    args = parser.parse_args()

    remove_domains(args.remove, args.from_file, args.out)
