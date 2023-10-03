use ark_bls12_377::constraints::G1Var;
use ark_ec::pairing::Pairing;
use ark_ff::Field;
use ark_r1cs_std::{fields::fp::FpVar, prelude::{AllocVar, EqGadget, CurveVar}, boolean};
use ark_relations::{
    lc,
    r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError},
};
use ark_std::UniformRand;

// circuit proving knowledge of a square root
// when generating the Setup, the element inside is None
#[derive(Clone, Debug)]
pub struct TestCircuit<E: Pairing>{
    x: Option<E::ScalarField>,
    y: Option<E::ScalarField>,
    result: Option<E::ScalarField>,
}
impl<E> ConstraintSynthesizer<E::ScalarField> for TestCircuit<E> 
where
    E:Pairing,
{
    fn generate_constraints(self, cs: ConstraintSystemRef<E::ScalarField>) -> Result<(), SynthesisError> {

        let x_var = FpVar::new_witness(cs.clone(), || Ok(self.x.unwrap())).unwrap();
        let y_var = FpVar::new_witness(cs.clone(), || Ok(self.y.unwrap())).unwrap();
        let result_var = FpVar::new_input(cs.clone(), || Ok(self.result.unwrap())).unwrap();
        let result = x_var+y_var;
        result_var.conditional_enforce_equal(&result, &boolean::Boolean::TRUE)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_377::Bls12_377;
    use ark_groth16::{prepare_verifying_key, Groth16};

    // no need to run these tests, they're just added as a guideline for how to
    // consume the circuit
    #[test]
    fn test_square_root() {
        test_square_root_curve::<Bls12_377>()
    }

    fn test_square_root_curve<E: Pairing>() {
        // This may not be cryptographically safe, use
        // `OsRng` (for example) in production software.
        let rng  = &mut ark_std::test_rng();
        let x = <E::ScalarField as From<u64>>::from(5);
        let y = <E::ScalarField as From<u64>>::from(5);
        let z = E::G1::rand(rng);
        let result = <E::ScalarField as From<u64>>::from(10);
        // Create parameters for our circuit
        let params = {
            let c = TestCircuit::<E>{
                x: None,
                y: None,
                result: None,
            };
            Groth16::<E>::generate_random_parameters_with_reduction(c, rng).unwrap()
        };
        let pvk = prepare_verifying_key(&params.vk);


        // Prover instantiates the circuit and creates a proof
        // with his RNG
        let c = TestCircuit::<E>{
            x: Some(x),
            y: Some(y),
            result: Some(result),
        };
        let proof = Groth16::<E>::create_random_proof_with_reduction(c, &params, rng).unwrap();

        // Verifier only needs to know 25 (the output, aka public input),
        // the vk and the proof!
        assert!(Groth16::<E>::verify_proof(&pvk, &proof, &[result]).unwrap());
    }
}