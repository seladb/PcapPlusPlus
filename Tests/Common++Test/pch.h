#pragma once

#include <array>
#include <memory>

#include <gtest/gtest.h>
#include <gmock/gmock.h>

// If PTF_NO_TEST_OVERRIDE is not defined, the header overrides the default Google Test
// test macro to include memory leak detection functionality.
#include "Utils/MemoryLeakDetectorFixture.hpp"
