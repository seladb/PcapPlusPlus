/*
 * features_cluster.cc
 *
 *  Created on: Nov 3, 2016
 *      Author: rvelea
 */

#include "cluster.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include <fstream>
#include <iostream>
#include <regex>
#include <vector>

using namespace std;

static int number_of_entries = 0;
static vector<string> csv_labels;

static int zero_count(const csv_entry *e)
{
	int zeros = 0;
	for (auto i : e->entries) {
		if (i == 0.0) {
			zeros++;
		}
	}

	return zeros;
}

static csv_entry_t *make_csv_entry(const char *csv_line)
{
	string line(csv_line);
	regex re("[\\s,]+");
	sregex_token_iterator it(line.begin(), line.end(), re, -1);
	sregex_token_iterator reg_end;

	csv_entry *e = new csv_entry;

	// Skip keys/description.
	e->addr1 = it->str();
	it++;
	e->addr2 = it->str();
	it++;

	e->count = 0;

	for (; it != reg_end; it++) {
		unsigned long long value = atoll(it->str().c_str());
		e->entries.push_back(value);
		e->original_values.push_back(value);
		e->count++;
	}

	return e;
}

static bool read_csv_file(const char *csv_file_path, vector<csv_entry_t *> &entries)
{
	ifstream csv(csv_file_path, ifstream::in);
	char header[256] = {0,};

	csv.getline(header, sizeof(header));

	string s(header);
	regex re("[\\s,]+");
	sregex_token_iterator it(s.begin(), s.end(), re, -1);
	sregex_token_iterator reg_end;

	for (; it != reg_end; it++) {
		csv_labels.push_back(it->str());
	}

	while (!csv.eof()) {
		char line[256] = {0,};
		csv.getline(line, sizeof(line));
		if (strlen(line) <= 1) {
			continue;
		}

		csv_entry_t *e = make_csv_entry(line);
		if (zero_count(e) == 0) {
			entries.push_back(e);
			number_of_entries++;
		}
		else {
			delete e;
		}
	}

	csv.close();

	return true;
}

static double rescale(const double &v, const double &min, const double &max)
{
	return (v - min) / (max - min);
}

static void scale_features(vector<csv_entry_t *> &entries)
{
	vector<double> min, max;
	csv_entry_t *reference = entries[0];

	for (auto d : reference->entries) {
		min.push_back(d);
		max.push_back(d);
	}

	for (auto it : entries) {
		csv_entry_t *current = it;
		for (unsigned i = 0; i < current->entries.size(); ++i) {
			if (min[i] > current->entries[i]) {
				min[i] = current->entries[i];
			}
			if (max[i] < current->entries[i]) {
				max[i] = current->entries[i];
			}
		}
	}

	for (auto it : entries) {
		csv_entry_t *current = it;
		for (unsigned i = 0; i < current->entries.size(); ++i) {
			current->entries[i] = rescale(current->entries[i], min[i], max[i]);
		}
	}
}

static void cluster_data(vector<csv_entry_t *> &data)
{
	for (auto i = 2; i < 8; ++i) {
		Galaxy g(i, data, data.size());
		g.compute_clusters();
		if (g.valid()) {
			printf("K-means algorithm for %d clusters has %.12lf total error.\n", i, g.get_error());
			g.print();
		}
	}
}

int main(int argc, const char **args) {

	if (argc < 2) {
		fprintf(stderr, "Please provide path to CSV in cmdline!\n");
		return 0;
	}

	vector<csv_entry_t *> entries;
	if (read_csv_file(args[1], entries) == false) {
		fprintf(stderr, "Unable to read input file %s\n", args[1]);
	}

	scale_features(entries);
	// Now we only have to deal with [0..1] values.

	cluster_data(entries);

	return 0;
}
