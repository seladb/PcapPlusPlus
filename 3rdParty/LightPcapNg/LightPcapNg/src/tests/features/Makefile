all: libfeatures.so features_cluster

libfeatures.so: *.c
	gcc -Wall -O2 -g -shared $^ -o $@ -Iinclude -fPIC -L. -llight_pcapng

features_cluster: features_cluster.cc cluster.cc
	g++ -std=c++11 -Wall -O2 -g $^ -o $@

clean:
	rm -rf libfeatures.so features_cluster