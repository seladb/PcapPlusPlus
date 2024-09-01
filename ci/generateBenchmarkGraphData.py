import json
import csv
import os
import argparse

# Set up argument parser
parser = argparse.ArgumentParser(
    description="Parse Google Benchmark results and write to CSV."
)
parser.add_argument(
    "--directory", type=str, help="Directory containing the JSON benchmark results"
)
parser.add_argument(
    "--output", type=str, help="Output CSV file path", default="benchmark_results.csv"
)
args = parser.parse_args()

# Directory containing the JSON files
directory = args.directory
csv_file = args.output

# List to store the parsed benchmark data
benchmark_data = []

# Iterate over each JSON file in the directory
for filename in os.listdir(directory):
    if filename.endswith(".json"):
        # Extract the commit SHA from the filename
        commit_sha = filename.split("_")[-1].split(".")[0]

        # Open and parse the JSON file
        with open(os.path.join(directory, filename), "r") as file:
            data = json.load(file)

        # Extract the benchmark results
        benchmarks = {
            "commit_sha": commit_sha,
            "BM_PcapFileRead": None,
            "BM_PcapFileWrite": None,
            "BM_PacketParsing": None,
            "BM_PacketCrafting": None,
        }

        for benchmark in data.get("benchmarks", []):
            if benchmark["name"] in benchmarks:
                benchmarks[benchmark["name"]] = benchmark.get("items_per_second", "N/A")

        # Append the results to the list
        benchmark_data.append(benchmarks)

# Write the collected data to the CSV file
with open(csv_file, "w", newline="") as file:
    writer = csv.DictWriter(
        file,
        fieldnames=[
            "commit_sha",
            "BM_PcapFileRead",
            "BM_PcapFileWrite",
            "BM_PacketParsing",
            "BM_PacketCrafting",
        ],
    )
    writer.writeheader()
    writer.writerows(benchmark_data)
