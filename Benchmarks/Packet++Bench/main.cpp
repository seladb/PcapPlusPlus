
#include <benchmark\benchmark.h>

int main(int argc, char** argv)
{
    // Initialize the benchmark library
    benchmark::Initialize(&argc, argv);
    
    // Run all benchmarks
    benchmark::RunSpecifiedBenchmarks();
    return 0;
}
