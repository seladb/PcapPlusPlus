# CPack runs this script once per component in component-install mode (DEB/RPM).
# These files are only meaningful for the single TGZ archive, so skip them when
# packaging individual components to avoid installing the same files into every package.
if(NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL ${CPACK_ADDITIONAL_INSTALL_RESOURCES} DESTINATION "${CMAKE_CURRENT_BINARY_DIR}")
  file(INSTALL ${CPACK_ADDITIONAL_EXAMPLE_APP} DESTINATION "${CMAKE_CURRENT_BINARY_DIR}/example-app")
endif()
