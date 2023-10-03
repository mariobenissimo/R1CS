
use ark_bls12_377::G1Projective;
use ark_bls12_377::Fq;
use ark_r1cs_std::R1CSVar;
use ark_r1cs_std::prelude::EqGadget;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_r1cs_std::*;
use ark_r1cs_std::alloc::AllocVar;
use ark_bls12_377::{*, constraints::*};
use ark_ff::PrimeField;
use ark_ec::pairing::Pairing;
use ark_r1cs_std::pairing::PairingVar;
use ark_r1cs_std::groups::CurveVar;
use rayon::result;
use std::marker::PhantomData;
use ark_std::UniformRand;
use ark_bls12_377::{*, constraints::*};
use ark_ec::CurveGroup;
pub type G2 = <Bls12_377 as Pairing>::G2Affine;

enum Op {
    Add,
    Sub,
}
// struct Prova<I, IV>
// where
//     I: Pairing,
//     IV: PairingVar<I>,
// {
//     x: I::G1,
//     y: I::G1,
//     z: I::G1, //Fqk
//     _iv: PhantomData<IV>,
//     _i: PhantomData<I>,
// }
// impl<I, IV> Clone for Prova<I, IV>
// where
//     I: Pairing,
//     IV: PairingVar<I>,
// {
//     fn clone(&self) -> Self {
//         Self {
//             x: self.x,
//             y: self.y,
//             z: self.z,    
//             _iv: self._iv,
//             _i: self._i,
//         }
//     }
// }
// impl<I, IV> ConstraintSynthesizer<I::ScalarField> for Prova<I, IV>
// where
//     I: Pairing,
//     IV: PairingVar<I>,
//     IV::G1Var: CurveVar<I::G1,I::BaseField>,
// {
//     fn generate_constraints(self, cs: ConstraintSystemRef<I::ScalarField>) -> Result<(), SynthesisError> {

//         // let x_var = IV::G1Var::new_witness(cs.clone(), || Ok(self.x))?;

//         // let y_var = IV::G1Var::new_witness(cs.clone(),|| Ok(self.y))?;
//         // let result_var =IV::G1Var::new_input(cs.clone(), || Ok(self.z))?;
//         //let result= x_var + y_var;
//         //result_var.enforce_equal(&result)?;
//         Ok(())
//     }
// }
fn main() -> Result<(), ark_relations::r1cs::SynthesisError> { 
    Ok(())
}
#[cfg(test)]
mod tests {

    // use ark_bls12_377::{constraints::PairingVar as IV, constraints::*, Bls12_377 as I};
    // use ark_groth16::Groth16;
    // use super::*;
    // use ark_ec::bls12::Bls12;
    // use ark_relations::r1cs::ConstraintSystem;
    // use ark_std::rand::{distributions::Uniform, Rng};
    // use rand_core::{OsRng, SeedableRng};
    // use ark_crypto_primitives::snark::SNARK;
    // use ark_ec::bls12::Bls12Config;
    // use ark_ff::{Field, PrimeField};
    // use ark_std::{One, UniformRand};
    // use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
    // use ark_test_curves::bls12_381::Bls12_381;
    // use ark_test_curves::pairing::Pairing;
    // use ark_bls12_377::constraints::FqVar;
    // #[test]
    // fn preimage_constraints_correctness() {
    //     let cs =
    //         ConstraintSystem::<<Bls12<ark_bls12_377::Config> as Pairing>::BaseField>::new_ref();
    //     let mut rng = ark_std::test_rng();

    //     let x = G1::rand(&mut rng);
    //     let y = G1::rand(&mut rng);
    //     let mut z = x + y;
    //     let circuit = Prova::<Bls12<ark_bls12_377::Config>,IV>{
    //         x,
    //         y,
    //         z,
    //         _iv: PhantomData,
    //         _i: PhantomData,
    //     };

    //     circuit.generate_constraints(cs.clone())
    //         .unwrap();

    //     assert!(cs.is_satisfied().unwrap());
    // }
    // #[test]
    // fn test_with_groth2() {
    
    //     let mut rng2 = rand_chacha::ChaChaRng::seed_from_u64(1776);
    //     let mut rng = ark_std::test_rng();

    //     let x = G1::rand(&mut rng);
    //     let y = G1::rand(&mut rng);
    //     let mut z = x + y;
    //     let circuit = Prova::<ark_bls12_377::Bls12_377,IV>{
    //         x,
    //         y,
    //         z,
    //         _iv: PhantomData,
    //         _i: PhantomData,
    //     };

    //     let (pk,vk) = Groth16::<ark_bls12_377::Bls12_377>::circuit_specific_setup(circuit.clone(), &mut rng2).unwrap();

    //     let proof = Groth16::<ark_bls12_377::Bls12_377>::prove(&pk, circuit.clone(), &mut OsRng).unwrap();
 
    //     let public_inputs = vec![circuit.z];
    //     let ok = Groth16::<ark_bls12_377::Bls12_377>::verify(&pk.vk, &public_inputs, &proof).unwrap();
    //     assert!(ok);
    // }
}


mod tests2 {
    use super::*;
    use ark_relations::r1cs::ConstraintSystem;
    use rand_core::SeedableRng;
    use ark_groth16::Groth16;
    use ark_crypto_primitives::snark::SNARK;
    use ark_groth16::r1cs_to_qap::LibsnarkReduction;
    #[test]
    fn test() -> Result<(), ark_relations::r1cs::SynthesisError> {
        let cs = ConstraintSystem::<Fq>::new_ref();
        let mut rng = ark_std::test_rng();
        let mut rng2 = rand_chacha::ChaChaRng::seed_from_u64(1776);

        // Generate random `G1` and `G2` elements.
        let a_native = G2::rand(&mut rng);
        let b_native = G2::rand(&mut rng);
        let result = a_native + b_native;
        // Allocate `a_native` and `b_native` as witness variables in `cs`.
        let a_var = G2Var::new_witness(ark_relations::ns!(cs, "a"), || Ok(a_native))?;
        let b_var = G2Var::new_witness(ark_relations::ns!(cs, "b"), || Ok(b_native))?;
        let result_var = G2Var::new_input(ark_relations::ns!(cs, "b"), || Ok(result))?;
        let result2 = a_var + b_var;
        result_var.enforce_equal(&result2)?;
        assert!(cs.is_satisfied()?);
        // let (pk, vk) = Groth16::<ark_bls12_377::Bls12_377>::circuit_specific_setup(
        //     (a_native,b_native,result),
        //     rng,
        // )
        // .unwrap();

        // let params = {
        //     Groth16::<Bls12_377>::generate_random_parameters_with_reduction((a_native,b_native,result), rng).unwrap()
        // };
        // let pvk = prepare_verifying_key(&params.vk);

        // // we know the square root of 25 -> 5
        // let out = <E::ScalarField as From<u64>>::from(25);
        // let input = <E::ScalarField as From<u64>>::from(5);

        // // Prover instantiates the circuit and creates a proof
        // // with his RNG
        // let c = TestCircuit::<E>(Some(input));
        // let proof = Groth16::<E>::create_random_proof_with_reduction(c, &params, rng).unwrap();

        // // Verifier only needs to know 25 (the output, aka public input),
        // // the vk and the proof!
        // assert!(Groth16::<E>::verify_proof(&pvk, &proof, &[out]).unwrap());


        Ok(())
    }
}