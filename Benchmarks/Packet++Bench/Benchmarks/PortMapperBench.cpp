#include <vector>
#include <benchmark\benchmark.h>

#include "ParserConfig.h"

namespace pcpp_bench
{
	using namespace pcpp;

	namespace
	{
		void PortMapperStaticLookupSingle(benchmark::State& state)
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
		BENCHMARK(PortMapperStaticLookupSingle);

		void PortMapperStaticLookupMatrix(benchmark::State& state)
		{
			ParserConfiguration& config = ParserConfiguration::getDefault();
			PortMapper& portMapper = config.portMapper;

			size_t totalLookups = 0;
			for (auto _ : state)
			{
				PortPair portPair(80, 443);
				auto matrix = portMapper.getMatchMatrix(portPair);
				benchmark::DoNotOptimize(matrix);
				totalLookups++;
			}
			state.SetItemsProcessed(totalLookups);
		}
		BENCHMARK(PortMapperStaticLookupMatrix);

		void PortMapperDynamicLookupSingle(benchmark::State& state)
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
		BENCHMARK(PortMapperDynamicLookupSingle);

		void PortMapperDynamicLookupMatrix(benchmark::State& state)
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

				auto matrix = portMapper.getMatchMatrix(portPair);
				benchmark::DoNotOptimize(matrix);
				totalLookups++;
			}

			state.SetItemsProcessed(totalLookups);
		}
		BENCHMARK(PortMapperDynamicLookupMatrix);
	}  // namespace
}  // namespace pcpp_bench
