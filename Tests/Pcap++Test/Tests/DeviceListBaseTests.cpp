#include "../TestDefinition.h"

#include "DeviceListBase.h"

namespace
{
	/// @brief A derived class of DeviceListBase used for testing purposes.
	template <class T> struct DerivedDeviceList : public pcpp::internal::DeviceListBase<T>
	{
		DerivedDeviceList() = default;
		explicit DerivedDeviceList(pcpp::PointerVector<T> devices)
		    : pcpp::internal::DeviceListBase<T>(std::move(devices))
		{}
	};

}  // namespace

PTF_TEST_CASE(TestDeviceListBase)
{
	using pcpp::internal::DeviceListBase;

	// Test the default constructor.
	DerivedDeviceList<int> deviceList;
	PTF_ASSERT_EQUAL(deviceList.size(), 0);
	PTF_ASSERT_TRUE(deviceList.begin() == deviceList.end());
	PTF_ASSERT_TRUE(deviceList.empty());

	// Test the constructor with a list of devices.
	pcpp::PointerVector<int> devices;
	int* dev0 = new int(0);
	int* dev1 = new int(1);
	int* dev2 = new int(2);
	devices.pushBack(dev0);
	devices.pushBack(dev1);
	devices.pushBack(dev2);
	DerivedDeviceList<int> deviceList2(std::move(devices));

	PTF_ASSERT_EQUAL(deviceList2.size(), 3);
	PTF_ASSERT_FALSE(deviceList2.empty());
	PTF_ASSERT_EQUAL(deviceList2.at(0), dev0);
	PTF_ASSERT_EQUAL(deviceList2.at(1), dev1);
	PTF_ASSERT_EQUAL(deviceList2.at(2), dev2);
	PTF_ASSERT_EQUAL(deviceList2.front(), dev0);
	PTF_ASSERT_EQUAL(deviceList2.back(), dev2);

	// Test iterators.
	{
		auto it = deviceList2.begin();
		PTF_ASSERT_EQUAL(*it, dev0);
		++it;
		PTF_ASSERT_EQUAL(*it, dev1);
		++it;
		PTF_ASSERT_EQUAL(*it, dev2);
		++it;
		PTF_ASSERT_TRUE(it == deviceList2.end());
	}

	// Test const iterators.
	{
		auto it = deviceList2.cbegin();
		PTF_ASSERT_EQUAL(*it, dev0);
		++it;
		PTF_ASSERT_EQUAL(*it, dev1);
		++it;
		PTF_ASSERT_EQUAL(*it, dev2);
		++it;
		PTF_ASSERT_TRUE(it == deviceList2.cend());
	}
}
