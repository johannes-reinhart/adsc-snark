add_executable(
        profile_folklore_adscsnark
        EXCLUDE_FROM_ALL

        profile_folklore_adscsnark.cpp;
)

target_link_libraries(
        profile_folklore_adscsnark

        snark
        ethsnarks_crypto
        ${Boost_LIBRARIES}
)



