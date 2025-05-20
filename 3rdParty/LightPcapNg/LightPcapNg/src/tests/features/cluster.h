/*
 * cluster.h
 *
 *  Created on: Nov 4, 2016
 *      Author: rvelea
 */

#ifndef SRC_TESTS_FEATURES_CLUSTER_H_
#define SRC_TESTS_FEATURES_CLUSTER_H_

#include <string>
#include <vector>

using namespace std;

typedef struct csv_entry {
	int count;
	string addr1, addr2;
	vector<double> entries;
	vector<unsigned long long> original_values;
} csv_entry_t;

class Cluster {
public:
	Cluster(const vector<double> values, int id = 0) : center(values), identifier(id) {}

	double distance(const vector<double> &x);
	void add_member(csv_entry_t *e, double dist) { members.push_back(e); error += dist; }
	void reset() { error = 0; members.clear(); }
	double recompute_center();
	int id() { return identifier; }
	int get_size() { return members.size(); }
	vector <double> &get_center() { return center; }
	double get_error() { return error; }

	virtual ~Cluster() {}

private:
	double error = 0;
	vector<double> center;
	vector<csv_entry_t *> members;
	int identifier;
};

class Galaxy {
public:
	Galaxy(int sz, vector<csv_entry_t *> &elements, int iter);
	void compute_clusters();
	double get_error() { return error; }
	bool valid() { return is_valid; }
	void print() const;
	virtual ~Galaxy() {}

private:
	double error = 0;
	int size;
	vector<Cluster *> clusters;
	vector<csv_entry_t *> &stars;
	int iterations;
	bool is_valid = false;
};

#endif /* SRC_TESTS_FEATURES_CLUSTER_H_ */
