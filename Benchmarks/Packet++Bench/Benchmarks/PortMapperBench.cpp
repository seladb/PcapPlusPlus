#include <vector>
#include <benchmark\benchmark.h>

#include "ParserConfig.h"

namespace pcpp_bench
{
	using namespace pcpp;

	namespace
	{
		namespace portmapper
		{
			void StaticLookupSingle(benchmark::State& state)
			{
				ParserConfiguration& config = ParserConfiguration::getDefault();
				PortMapper& portMapper = config.portMapper;

				size_t totalLookups = 0;
				for (auto _ : state)
				{
					PortPair portPair(80, 443);
					auto protocol = portMapper.getProtocolByPortPair(portPair);
					benchmark::DoNotOptimize(protocol);
					totalLookups++;
				}

				state.SetItemsProcessed(totalLookups);
			}
			BENCHMARK(StaticLookupSingle);

			void StaticLookupMatrix(benchmark::State& state)
			{
				ParserConfiguration& config = ParserConfiguration::getDefault();
				PortMapper& portMapper = config.portMapper;

				size_t totalLookups = 0;
				for (auto _ : state)
				{
					PortPair portPair(80, 443);
					auto matrix = portMapper.getProtocolMappingsMatrixForPortPair(portPair);
					benchmark::DoNotOptimize(matrix);
					totalLookups++;
				}
				state.SetItemsProcessed(totalLookups);
			}
			BENCHMARK(StaticLookupMatrix);

			void DynamicLookupSingle(benchmark::State& state)
			{
				ParserConfiguration& config = ParserConfiguration::getDefault();
				PortMapper& portMapper = config.portMapper;
				size_t totalLookups = 0;

				// Generate random port pairs for dynamic lookups
				std::vector<PortPair> inputPorts{
					PortPair{ 80, 65440 },
					PortPair{ 64000, 64002 },
				};

				for (auto _ : state)
				{
					// Simulate dynamic port pairs by cycling through a predefined set
					PortPair const& portPair = inputPorts[totalLookups % inputPorts.size()];

					auto protocol = portMapper.getProtocolByPortPair(portPair);
					benchmark::DoNotOptimize(protocol);
					totalLookups++;
				}

				state.SetItemsProcessed(totalLookups);
			}
			BENCHMARK(DynamicLookupSingle);

			void DynamicLookupMatrix(benchmark::State& state)
			{
				ParserConfiguration& config = ParserConfiguration::getDefault();
				PortMapper& portMapper = config.portMapper;
				size_t totalLookups = 0;

				// Generate random port pairs for dynamic lookups
				std::vector<PortPair> inputPorts{
					PortPair{ 80, 65440 },
					PortPair{ 64000, 64002 },
				};

				for (auto _ : state)
				{
					// Simulate dynamic port pairs by cycling through a predefined set
					PortPair const& portPair = inputPorts[totalLookups % inputPorts.size()];

					auto matrix = portMapper.getProtocolMappingsMatrixForPortPair(portPair);
					benchmark::DoNotOptimize(matrix);
					totalLookups++;
				}

				state.SetItemsProcessed(totalLookups);
			}
			BENCHMARK(DynamicLookupMatrix);
		}  // namespace portmapper
	}  // namespace
}  // namespace pcpp_bench
