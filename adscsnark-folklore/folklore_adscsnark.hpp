/** @file
*****************************************************************************

Declaration of interfaces for folklore ADSC-SNARK

An ADSC-SNARK proves iterative and stateful computations on authenticated data

The folklore ADSC-SNARK extends a regular R1CS relation with a relation
for a signature verification and for a collision-resistant hash function
in order to make proofs on authenticated data and with state consistency


*****************************************************************************/

#ifndef FOLKLORE_ADSCSNARK_HPP_
#define FOLKLORE_ADSCSNARK_HPP_

#include <vector>

#include "depends/libsnark/libsnark/zk_proof_systems/ppzksnark/r1cs_gg_ppzksnark/r1cs_gg_ppzksnark.hpp"
#include "depends/libsnark/libsnark/relations/constraint_satisfaction_problems/r1cs/r1cs_ext.hpp"
#include "crypto/signatures/eddsa.h"

#include "signature_gadget.hpp"
#include "state_gadget.hpp"
#include "sequence_check_gadget.hpp"

template<typename ppT>
using folklore_adscsnark_constraint_system = libsnark::r1cs_adsc_constraint_system<libff::Fr<ppT> >;

template<typename ppT>
using folklore_adscsnark_primary_input = libsnark::r1cs_primary_input<libff::Fr<ppT> >;

template<typename ppT>
using folklore_adscsnark_auxiliary_input = libsnark::r1cs_auxiliary_input<libff::Fr<ppT> >;

template<typename ppT>
using folklore_adscsnark_variable_assignment = libsnark::r1cs_variable_assignment<libff::Fr<ppT> >;

template<typename ppT>
using folklore_adscsnark_proving_key = libsnark::r1cs_gg_ppzksnark_proving_key<ppT>;

template<typename ppT>
using folklore_adscsnark_verification_key = libsnark::r1cs_gg_ppzksnark_verification_key<ppT>;

template<typename ppT>
using folklore_adscsnark_processed_verification_key = libsnark::r1cs_gg_ppzksnark_processed_verification_key<ppT>;

template<typename ppT>
using folklore_adscsnark_authentication_key = ethsnarks::eddsa_private_key;

template<typename ppT>
using folklore_adscsnark_signature = ethsnarks::EddsaSignature;

template<typename ppT>
class folklore_adscsnark_proof;

template<typename ppT>
std::ostream& operator<<(std::ostream &out, const folklore_adscsnark_proof<ppT> &proof);

template<typename ppT>
std::istream& operator>>(std::istream &in, folklore_adscsnark_proof<ppT> &proof);

/**
 * Proof for the folklore ADSC-SNARK consisting of
 * snark_proof: the proof of the underlying SNARK
 * hash: the digest of the state
 */
template<typename ppT>
class folklore_adscsnark_proof {
public:
    libsnark::r1cs_gg_ppzksnark_proof<ppT> snark_proof;
    libff::Fr<ppT> hash;
    friend std::ostream& operator<< <ppT>(std::ostream &out, const folklore_adscsnark_proof<ppT> &proof);
    friend std::istream& operator>> <ppT>(std::istream &in, folklore_adscsnark_proof<ppT> &proof);
};

/**
 * Keys for the folklore ADSC-SNARK
 * including proving, verification and a list of authentication keys,
 * as well as an initial proof for the verifier
 */
template<typename ppT>
class folklore_adscsnark_keypair {
public:
    folklore_adscsnark_proving_key<ppT> pk;
    folklore_adscsnark_verification_key<ppT> vk;
    std::vector<folklore_adscsnark_authentication_key<ppT>> aks;
    folklore_adscsnark_proof<ppT> initial_proof;
};

/**
 * Relation for the folklore ADSC-SNARK
 * This structure contains the original relation and additional gadgets for
 * signature verification and hashing
 */
template<typename FieldT>
struct folklore_adscsnark_relation {
    std::map<size_t, size_t> variable_map; // Maps original variables to new variables
    libsnark::protoboard<FieldT> pb;
    libsnark::pb_variable<FieldT> state_in_digest;
    libsnark::pb_variable<FieldT> state_out_digest;
    pb_state<FieldT> counter;
    std::shared_ptr<state_gadget<FieldT>> s_gadget;
    std::vector<signature_gadget<FieldT>> signature_gadgets;
    std::shared_ptr<sequence_check_gadget<FieldT>> sc_gadget;
    size_t primary_input_size;
    size_t private_input_size;
    size_t state_size;
    size_t witness_size;
    size_t iterations;
    libsnark::r1cs_constraint_system<FieldT> constraint_system;
};

/***************************** Main algorithms *******************************/

/**
 * Generator algorithm for the folklore ADSC-SNARK, generate keys for authenticating inputs
 *
 * This part is separated from the actual generator, as the keys are also required for the
 * relation reduction (r1cs_example_to_r1cs_folklore_adsc), as public keys are baked into
 * the relation for better efficiency
 */
template<typename ppT>
std::vector<ethsnarks::eddsa_keypair> folklore_adscsnark_generator_auth(const std::vector<size_t> &private_input_blocks=std::vector<size_t>());

/**
 * Relation reduction for folklore ADSC-SNARK
 *
 * this routine adds signature verification and hash functions
 * to the base relation
 */
template<typename ppT>
folklore_adscsnark_relation<libff::Fr<ppT>> r1cs_example_to_r1cs_folklore_adsc(const libsnark::r1cs_adsc_example<libff::Fr<ppT> > &example, const std::vector<ethsnarks::eddsa_keypair> &keys, const std::vector<size_t> &private_input_blocks=std::vector<size_t>());

/**
 * Authenticator algorithm for the folklore ADSC-SNARK
 */
template<typename ppT>
folklore_adscsnark_signature<ppT> folklore_adscsnark_authenticate(const folklore_adscsnark_authentication_key<ppT> &ak, size_t iteration, const std::vector<libff::Fr<ppT>> &values);

/**
 * Generator algorithm for the folklore ADSC-SNARK
 */
template<typename ppT>
folklore_adscsnark_keypair<ppT> folklore_adscsnark_generator(folklore_adscsnark_relation<libff::Fr<ppT>> &relation,
                                                           const folklore_adscsnark_variable_assignment<ppT> &initial_state,
                                                           const std::vector<ethsnarks::eddsa_keypair> &keys);

/**
 * Proving algorithm for the folklore ADSC-SNARK
 */
template<typename ppT>
folklore_adscsnark_proof<ppT> folklore_adscsnark_prover(const folklore_adscsnark_proving_key<ppT> &pk,
                                                          folklore_adscsnark_relation<libff::Fr<ppT>> &relation,
                                                          const folklore_adscsnark_primary_input<ppT> &primary_input,
                                                          const folklore_adscsnark_variable_assignment<ppT> private_input,
                                                          const folklore_adscsnark_variable_assignment<ppT> state_assignment,
                                                          const folklore_adscsnark_variable_assignment<ppT> witness_assignment,
                                                          const std::vector<folklore_adscsnark_signature<ppT>> &signatures);

/**
 * Verifier algorithm, preprocessing step for the folklore ADSC-SNARK
 *
 * one time preprocessing of verifier key
 */
template<typename ppT>
folklore_adscsnark_processed_verification_key<ppT> folklore_adscsnark_verifier_process_vk(const folklore_adscsnark_verification_key<ppT> &vk);

/**
 * Verifier algorithm, online step for the folklore ADSC-SNARK
 */
template<typename ppT>
bool folklore_adscsnark_online_verifier(const folklore_adscsnark_processed_verification_key<ppT> &pvk,
                                                     const folklore_adscsnark_primary_input<ppT> &primary_input,
                                                     const folklore_adscsnark_proof<ppT> &proof,
                                                     const folklore_adscsnark_proof<ppT> &proof_previous);

#include "folklore_adscsnark.tcc"
#endif // FOLKLORE_ADSCSNARK_HPP_



