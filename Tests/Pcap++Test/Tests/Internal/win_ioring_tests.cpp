#include "../../TestDefinition.h"
#include "../../../../Pcap++/src/fileio/win_ioring.h"
#include <fstream>

PTF_TEST_CASE(TestWindowsIoRingDriver)
{
	using pcpp::internal::WindowsIoRingDriver;

	WindowsIoRingDriver::IoRingConfig config;
	config.bufferSize = 32;  // small buffer size for testing

	WindowsIoRingDriver ioRingDriver(config);

	// Create a temporary file with some data
	std::ofstream tempFile("temp_test_file.bin", std::ios::binary);
	for (int i = 0; i < 256; ++i)
	{
		tempFile << "This is a test file for WindowsIoRingDriver. T:" << i << "\n";
	}
	tempFile.close();

	PTF_ASSERT_TRUE(ioRingDriver.open("temp_test_file.bin"));

	std::vector<char> buffer(72);

	while(!ioRingDriver.isEof())
	{
		auto readBytes2 = ioRingDriver.readBytes(buffer.data(), buffer.size());
		//std::cout << std::string(buffer.data(), readBytes2);
	}

	ioRingDriver.close();
}