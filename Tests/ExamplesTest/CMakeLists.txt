find_package(
  Python
  COMPONENTS Interpreter
  REQUIRED)

set(PCAPPP_TESTS_EXAMPLESTEST_ARGS "--interface;eth0" CACHE STRING "Arguments passed to ExamplesTest")

add_test(
  NAME UpgradePip
  COMMAND ${Python_EXECUTABLE} -m pip install -U pip
)

add_test(
  NAME PythonRequirements
  COMMAND ${Python_EXECUTABLE} -m pip install -r "${CMAKE_CURRENT_SOURCE_DIR}/requirements.txt"
)

set_tests_properties(PythonRequirements PROPERTIES DEPENDS "UpgradePip")

add_test(
  NAME ExamplesTest
  COMMAND ${Python_EXECUTABLE} -m pytest "${CMAKE_CURRENT_SOURCE_DIR}" --root-path "${PCAPPP_BINARY_EXAMPLES_DIR}" ${PCAPPP_TESTS_EXAMPLESTEST_ARGS}
  WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}")
