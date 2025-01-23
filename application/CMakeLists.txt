add_executable(
        controller_scenario
        EXCLUDE_FROM_ALL

        controller/controller_scenario.cpp
        controller/scenario_network.cpp
        gadgets/utils.cpp
)

target_link_libraries(
        controller_scenario

        snark
        snark_crypto
        ${Boost_LIBRARIES}
)


