/*
 * cluster.cc
 *
 *  Created on: Nov 4, 2016
 *      Author: rvelea
 */

#include "cluster.h"

#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#define EPSILON 0.00000001

double Cluster::distance(const vector<double> &x)
{
	double distance = 0;
	for (unsigned i = 0; i < x.size(); ++i) {
		double diff = x[i] - center[i];
		distance += diff * diff;
	}

	return distance;
}

double Cluster::recompute_center()
{
	if (members.size() == 0) {
		return 0;
	}

	double center_diff = 0.0;

	for (unsigned i = 0; i < center.size(); ++i) {
		double sum = 0.0;
		for (auto it : members) {
			vector <double> &vals = it->entries;
			sum += vals[i];
		}

		sum /= members.size();
		center_diff += (center[i] - sum) * (center[i] - sum);
		center[i] = sum;
	}

	return center_diff;
}

Galaxy::Galaxy(int sz, vector<csv_entry_t *> &elements, int iter) : size(sz), stars(elements), iterations(iter)
{
	srand(time(NULL));
}

void Galaxy::compute_clusters()
{
	int world_size = stars.size();

	error = 1000000.0;

	for (auto iteration = 0; iteration < iterations; ++iteration) {
		vector<Cluster *> current_clusters;

		int failures = 0;

		// printf("Start reinitialization!\n");

		// Randomly initialize clusters.
		for (auto i = 0; i < size; ++i) {
			int random = rand() % world_size;
			bool valid = true;

			for (auto c : current_clusters) {
				if (c->id() == random || c->distance(stars[random]->entries) <= EPSILON) {
					if (failures >= world_size / size) {
						// printf("Failed to find enough entropy for %d centers!\n", size);

						// Some clean-up.
						while (!current_clusters.empty()) {
							Cluster *tmp = current_clusters.back();
							current_clusters.pop_back();
							delete tmp;
						}

						return;
					}

					valid = false;
					break;
				}
			}

			if (valid == true) {
				Cluster *new_cluster = new Cluster(stars[random]->entries, random);
				current_clusters.push_back(new_cluster);
			}
			else {
				failures++;
				i--;
			}
		}

		// printf("Successfully initialized centers!\n");

		double convergence_error = 1000000.0;

		while (convergence_error * convergence_error > EPSILON) {
			convergence_error = 0.0;

			for (auto i = 0; i < size; ++i) {
				current_clusters[i]->reset();
			}

			for (auto i = 0; i < world_size; ++i) {
				csv_entry_t *current_element = stars[i];
				double min_distance = 1000000.0;
				int index = -1;
				for (auto j = 0; j < size; ++j) {
					double d = current_clusters[j]->distance(current_element->entries);
					if (d < min_distance) {
						min_distance = d;
						index = j;
					}
				}
				current_clusters[index]->add_member(current_element, min_distance);
			}

			for (auto i = 0; i < size; ++i) {
				convergence_error += current_clusters[i]->recompute_center();
			}
		}

		// printf("Total error computed for %d iteration = %.12lf\n", iteration, convergence_error);

		double current_error = 0.0;
		for (auto c : current_clusters) {
			current_error += c->get_error();
		}

		if (error > current_error) {
			is_valid = true;

			while (!clusters.empty()) {
				Cluster *tmp = clusters.back();
				clusters.pop_back();
				delete tmp;
			}

			clusters = current_clusters;
			error = current_error;
		}
		else {
			while (!current_clusters.empty()) {
				Cluster *tmp = current_clusters.back();
				current_clusters.pop_back();
				delete tmp;
			}
		}
	}
}

void Galaxy::print() const
{
	printf("Current \"Galaxy\" has %d clusters and a total population of %lu:\n", size, stars.size());
	for (auto i : clusters) {
		printf("\t(");
		for (unsigned j = 0; j < i->get_center().size(); ++j) {
			printf("%.8lf, ", i->get_center().at(j));
		}
		printf(") has %u elements\n", i->get_size());
	}
	printf("\n\n");
}
