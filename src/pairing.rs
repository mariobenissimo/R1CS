use ark_ec::{
    pairing::{Pairing, PairingOutput},
    CurveGroup,
};

use ark_r1cs_std::prelude::*;
use ark_relations::{
    ns,
    r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError},
};

use ark_relations::r1cs::Namespace;
use ark_std::{
    marker::PhantomData,
    rand::{CryptoRng, Rng},
    UniformRand,
};
use std::borrow::Borrow;

#[derive(Copy, Clone)]
struct KeyVerification<I, IV>
where
    I: Pairing,
    IV: PairingVar<I>,
{
    x: Option<I::G1>,
    y: Option<I::G2>,
    z: Option<PairingOutput<I>>, //Fqk
    _iv: Option<PhantomData<IV>>,
    _i: Option<PhantomData<I>>,
}

impl<I, IV> KeyVerification<I, IV>
where
    I: Pairing,
    IV: PairingVar<I>,
    IV::G1Var: CurveVar<I::G1, I::BaseField>,
    IV::G2Var: CurveVar<I::G2, I::BaseField>,
{
    #[allow(dead_code)]
    pub fn new<R: Rng>(mut rng: R) -> Self {
        let x = I::G1::rand(&mut rng);
        let y = I::G2::rand(&mut rng);
        let x_prep = I::G1Prepared::from(x);
        let y_prep = I::G2Prepared::from(y);
        let z = I::pairing(x_prep, y_prep);

        Self {
            x: Some(x),
            y: Some(y),
            z: Some(z),
            _iv: Some(PhantomData),
            _i: Some(PhantomData),
        }
    }
}
impl<I, IV> ConstraintSynthesizer<<I as Pairing>::BaseField> for KeyVerification<I, IV>
where
    I: Pairing,
    IV: PairingVar<I>,
    IV::G1Var: CurveVar<I::G1, I::BaseField>,
    IV::G2Var: CurveVar<I::G2, I::BaseField>,
    IV::GTVar: FieldVar<I::TargetField, I::BaseField>,
{
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<<I as Pairing>::BaseField>,
    ) -> Result<(), SynthesisError> {
        let xvar = IV::G1Var::new_input(cs.clone(), || Ok(self.x.unwrap()))?;

        let yvar = IV::G2Var::new_input(cs.clone(), || Ok(self.y.unwrap()))?;

        let exp_res = IV::GTVar::new_input(cs.clone(), || Ok(self.z.unwrap().0))?; // here

        let x_prepared = IV::prepare_g1(&xvar)?;
        let y_prepared = IV::prepare_g2(&yvar)?;

        let pair = IV::pairing(x_prepared, y_prepared)?;

        exp_res.enforce_equal(&pair)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {

    /// Specifies the constraints for computing a pairing in a BLS12 bilinear group
    use crate::pairing::Pairing;
    use ark_bls12_377::{constraints::PairingVar as IV, constraints::*, Bls12_377 as I};

    use super::*;
    use ark_ec::bls12::Bls12;
    use ark_relations::r1cs::ConstraintSystem;
    use ark_std::rand::{distributions::Uniform, Rng};

    //#[test]
    // fn preimage_constraints_correctness() {
    //     let cs =
    //         ConstraintSystem::<<Bls12<ark_bls12_377::Config> as Pairing>::BaseField>::new_ref();
    //     let mut rng = ark_std::test_rng();

    //     KeyVerification::<I, IV>::new(&mut rng)
    //         .generate_constraints(cs.clone())
    //         .unwrap();

    //     assert!(cs.is_satisfied().unwrap());
    // }
}
mod testGroth {

    use ark_crypto_primitives::snark::SNARK;
    use ark_groth16::{Groth16};
    use ark_r1cs_std::fields::nonnative::params;
    use crate::pairing::Pairing;
    // use ark_bls12_377::{constraints::PairingVar as IV, constraints::*, Bls12_377 as I};
    use ark_bls12_377::{Bls12_377, Fr, Config};
    use super::*;
    use ark_ec::bls12::Bls12;
    use ark_relations::r1cs::ConstraintSystem;
    use ark_std::rand::{distributions::Uniform, Rng};
    
    #[test]
    fn test_prove_and_verify()
    {   
        let mut rng = ark_std::test_rng();
        let x = <Bls12<ark_bls12_377::Config> as Pairing>::G1::rand(&mut rng);
        let y = <Bls12<ark_bls12_377::Config> as Pairing>::G2::rand(&mut rng);
        let x_prep = <Bls12<ark_bls12_377::Config> as Pairing>::G1Prepared::from(x);
        let y_prep =<Bls12<ark_bls12_377::Config> as Pairing>::G2Prepared::from(y);
        let z = Bls12_377::pairing(x_prep, y_prep);

        let mut rng2 = ark_std::test_rng();
        let params = {
            let c = KeyVerification::<Bls12_377,ark_bls12_377::constraints::PairingVar>{
                x: None,
                y: None,
                z: None,
                _iv: None,
                _i: None,
            };
            Groth16::<Bls12_377>::generate_random_parameters_with_reduction(c, &mut rng2).unwrap()
        };
        // let pvk = prepare_verifying_key(&params.vk);


        // // Prover instantiates the circuit and creates a proof
        // // with his RNG
        // let c = TestCircuit::<E>{
        //     x: Some(x),
        //     y: Some(y),
        //     z: Some(z),
        //     result: Some(result),
        // };
        // let proof = Groth16::<E>::create_random_proof_with_reduction(c, &params, rng).unwrap();

        // // Verifier only needs to know 25 (the output, aka public input),
        // // the vk and the proof!
        // assert!(Groth16::<E>::verify_proof(&pvk, &proof, &[result]).unwrap());
    }
}
