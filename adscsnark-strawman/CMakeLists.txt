add_executable(
        profile_strawman_adscsnark
        EXCLUDE_FROM_ALL

        profile_strawman_adscsnark.cpp;
)

target_link_libraries(
        profile_strawman_adscsnark

        snark
        ethsnarks_crypto
        ${Boost_LIBRARIES}
)



