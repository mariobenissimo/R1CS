
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
    use ark_groth16::{prepare_verifying_key, Groth16};

    #[test]
    fn test_square_root() {
        test_square_root_curve::<Bls12_377>()
    }

    fn test_square_root_curve<E: Pairing>() {
        let rng = &mut ark_std::test_rng();
        let x = <E::ScalarField as From<u64>>::from(5);
        let y = <E::ScalarField as From<u64>>::from(5);
        let result = <E::ScalarField as From<u64>>::from(10);
        let params = {
            let c = TestCircuit::<E> {
                x: None,
                y: None,
                result: None,
            };
            Groth16::<E>::generate_random_parameters_with_reduction(c, rng).unwrap()
        };
        let pvk = prepare_verifying_key(&params.vk);
        println!("QUI");
        let c = TestCircuit::<E> {
            x: Some(x),
            y: Some(y),
            result: Some(result),
        };
        let proof = Groth16::<E>::create_random_proof_with_reduction(c, &params, rng).unwrap();

        assert!(Groth16::<E>::verify_proof(&pvk, &proof, &[result]).unwrap());
    }
}
