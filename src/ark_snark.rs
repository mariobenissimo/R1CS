// proving i know a scalar field which equals the sums of two scalar fields

use ark_bls12_377::constraints::G1Var;
use ark_ec::pairing::Pairing;

use ark_r1cs_std::{
    boolean,
    fields::fp::FpVar,
    prelude::{AllocVar, EqGadget},
};
use ark_relations::{
    lc,
    r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError},
}; 


#[derive(Clone, Debug)]
pub struct TestCircuit<E: Pairing> {
    x: Option<E::ScalarField>,
    y: Option<E::ScalarField>,
    result: Option<E::ScalarField>,
}
impl<E> ConstraintSynthesizer<E::ScalarField> for TestCircuit<E>
where
    E: Pairing,
{
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<E::ScalarField>,
    ) -> Result<(), SynthesisError> {
        let x_var = FpVar::new_witness(cs.clone(), || Ok(self.x.unwrap())).unwrap();
        let y_var = FpVar::new_witness(cs.clone(), || Ok(self.y.unwrap())).unwrap();
        let result_var = FpVar::new_input(cs.clone(), || Ok(self.result.unwrap())).unwrap();
    
        println!("{}", cs.num_instance_variables());
        println!("{}", cs.num_witness_variables());

        let result = x_var + y_var;
        result_var.conditional_enforce_equal(&result, &boolean::Boolean::TRUE)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_377::Bls12_377;
    //use ark_bls12_377::constraints::PairingVar;
    use ark_groth16::{prepare_verifying_key, Groth16};
    use ark_r1cs_std::bits::boolean::Boolean;
    use ark_r1cs_std::{alloc::AllocVar, eq::EqGadget};
    use ark_relations::{
        lc, ns,
        r1cs::{ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef, SynthesisError},
    };
    use ark_relations::r1cs::Field;
    use ark_test_curves::CurveGroup;
    use rand_core::SeedableRng;
    use ark_groth16::constraints::{Groth16VerifierGadget};
    use ark_crypto_primitives::snark::constraints::SNARKGadget;
    use ark_crypto_primitives::snark::SNARK;
    use ark_r1cs_std::prelude::PairingVar;
    type BasePrimeField<E> = <<<E as Pairing>::G1 as CurveGroup>::BaseField as Field>::BasePrimeField;


    #[test]
    fn test_square_root() {
        test_square_root_curve2::<Bls12_377, ark_bls12_377::constraints::PairingVar>()
    }

    fn test_square_root_curve2<E,IV>() 
    where
    E: Pairing,
    IV: PairingVar<E, BasePrimeField<E>>,
    {
        let mut rng2 = rand_chacha::ChaChaRng::seed_from_u64(1776);
        let rng = &mut ark_std::test_rng();
        let x = E::ScalarField::from(5 as u64);
        let y = E::ScalarField::from(5 as u64);
        let result = E::ScalarField::from(10 as u64);
        let c = TestCircuit::<E> {
            x: Some(x),
            y: Some(y),
            result: Some(result),
        };
        let (pk, vk) = Groth16::<E>::circuit_specific_setup(c.clone(), &mut rng2).unwrap();
        let proof = Groth16::<E>::prove(&pk, c.clone(), &mut rng2).unwrap();
        assert!(
            Groth16::<E>::verify(&vk, &[result], &proof).unwrap(),
            "The native verification check fails."
        );
        let cs_sys = ConstraintSystem::<BasePrimeField<E>>::new();
        let cs = ConstraintSystemRef::new(cs_sys);
        let input_gadget= <Groth16VerifierGadget<E, IV> as SNARKGadget<E::ScalarField,BasePrimeField<E>,Groth16<E>>>::InputVar::new_input(ns!(cs, "new_input"), || Ok(vec![result])).unwrap();
        let proof_gadget = <Groth16VerifierGadget<E, IV> as SNARKGadget<E::ScalarField,BasePrimeField<E>,Groth16<E>>>::ProofVar::new_witness(ns!(cs, "alloc_proof"), || Ok(proof)).unwrap();
        let vk_gadget = <Groth16VerifierGadget<E, IV> as SNARKGadget<E::ScalarField,BasePrimeField<E>,Groth16<E>>>::VerifyingKeyVar::new_constant(ns!(cs, "alloc_vk"), vk.clone()).unwrap();
        let ver = <Groth16VerifierGadget<E, IV> as SNARKGadget<E::ScalarField,BasePrimeField<E>,Groth16<E>>>::verify(&vk_gadget, &input_gadget, &proof_gadget).unwrap();
        ver.enforce_equal(&Boolean::constant(true)).unwrap();
    }
}
