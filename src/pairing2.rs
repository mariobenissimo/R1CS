use ark_bls12_377::{constraints::G1Var, G1Affine};
use ark_ec::{pairing::Pairing, bls12::Bls12Config};
use ark_r1cs_std::{prelude::{PairingVar, FieldVar}, R1CSVar};
use ark_ff::Field;
use ark_r1cs_std::{fields::fp::FpVar, prelude::{AllocVar, EqGadget, CurveVar, AllocationMode}, boolean};
use ark_relations::{
    lc,
    r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError},
};
use std::marker::PhantomData;
use ark_ec::CurveGroup;
type BasePrimeField<E> = <<E as Pairing>::G1 as CurveGroup>::BaseField;

#[derive(Clone, Debug)]
pub struct TestCircuit<E,IV>
where
    E: Pairing,
    IV: PairingVar<E,BasePrimeField<E>>,
{
    a: Option<E::G1Prepared>,
    b: Option<E::G2Prepared>, 
    result: Option<E::TargetField>,
    _iv: Option<PhantomData<IV>>,
}
impl<E,IV> ConstraintSynthesizer<BasePrimeField<E>> for TestCircuit<E,IV>
where
E: Pairing,
IV: PairingVar<E,BasePrimeField<E>>,
IV::G1PreparedVar: AllocVar<E::G1Prepared, BasePrimeField<E>>,
IV::G2PreparedVar: AllocVar<E::G2Prepared, BasePrimeField<E>>,
IV::GTVar: FieldVar<E::TargetField, BasePrimeField<E>>
{
    fn generate_constraints(self, cs: ConstraintSystemRef<BasePrimeField<E>>) -> Result<(), SynthesisError> {

        let a_var = IV::G1PreparedVar::new_witness(cs.clone(), || Ok(self.a.unwrap())).unwrap();  
        let b_var = IV::G2PreparedVar::new_witness(cs.clone(), || Ok(self.b.unwrap())).unwrap(); 
        let result_var = IV::GTVar::new_input(cs.clone(), || Ok(self.result.unwrap())).unwrap(); 
        let result = IV::pairing(a_var, b_var).unwrap();      
        result_var.enforce_equal(&result);
         Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_377::{Bls12_377};
    use ark_groth16::{Groth16};
    use ark_bls12_377::{constraints::PairingVar as IV, constraints::*, Bls12_377 as I};
    // no need to run these tests, they're just added as a guideline for how t
    #[test]
    fn test_square_root_curve() {
        let rng  = &mut ark_std::test_rng();
        let params = {
            let c = TestCircuit::<I,IV>{
                a: None,
                b: None,
                result: None,
                _iv: None,
            };
            Groth16::<Bls12_377>::generate_random_parameters_with_reduction(c, rng).unwrap()
        };

        //ERROR
        // type mismatch resolving `<Projective<Config> as CurveGroup>::BaseField == Fp<MontBackend<FrConfig, 4>, 4>`
        //expected struct `Fp<MontBackend<ark_bls12_377::FrConfig, 4>, 4>`
        //found struct `Fp<MontBackend<ark_bls12_377::FqConfig, 6>, 6>


        // let pvk = prepare_verifying_key(&params.vk);
        // // Prover instantiates the circuit and creates a proof
        // // with his RNG
        // let c = TestCircuit::<E>{
        //     x: Some(x),
        //     y: Some(y),
        //     result: Some(result),
        // };
        // let proof = Groth16::<E>::create_random_proof_with_reduction(c, &params, rng).unwrap();

        // // Verifier only needs to know 25 (the output, aka public input),
        // // the vk and the proof!
        // assert!(Groth16::<E>::verify_proof(&pvk, &proof, &[result]).unwrap());
    }
}