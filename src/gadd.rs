use ark_bls12_377::constraints::G1Var;
use ark_ec::{AffineRepr, Group};
use ark_ec::{
    pairing::{prepare_g1, prepare_g2, MillerLoopOutput, Pairing, PairingOutput},
    CurveGroup,
};
use ark_ff::Field;
use ark_ff::{biginteger::BigInteger64 as B, BigInteger as _};
use ark_ff::{BigInt, PrimeField};
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::Namespace;
use ark_relations::{
    ns,
    r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError},
};
use ark_std::{
    marker::PhantomData,
    rand::{CryptoRng, Rng},
    UniformRand,
};
use std::{
    borrow::Borrow,
    ops::{Mul, MulAssign},
};

struct PairingVerification<I, IV>
where
    I: Pairing,
    IV: PairingVar<I>,
{
    pubs: Option<Vec<I::G1>>,
    result: Option<I::G1>,
    _iv: Option<PhantomData<IV>>,
    _i: Option<PhantomData<I>>,
}

impl<I, IV> Clone for PairingVerification<I, IV>
where
    I: Pairing,
    IV: PairingVar<I>,
{
    fn clone(&self) -> Self {
        Self {
            pubs: self.pubs.clone(),
            result: self.result,
            _iv: self._iv,
            _i: self._i,
        }
    }
}

impl<I, IV> PairingVerification<I, IV>
where
    I: Pairing,
    IV: PairingVar<I>,
{
    #[allow(dead_code)]
    pub fn new<R: Rng>(mut rng: R) -> Self {
        let a = I::G1::rand(&mut rng);
        let b = I::G1::rand(&mut rng);
        let mut pubs = Vec::new();
        // Add two values to the vec.
        pubs.push(a);
        pubs.push(b);

        let result = a + b;
        // ... and check that the two representations are equal.
        assert_eq!(a + b, result);
        Self {
            pubs: Some(pubs),
            result: Some(result),
            _iv: Some(PhantomData),
            _i: Some(PhantomData),
        }
    }
}
impl<I, IV> ConstraintSynthesizer<<I as Pairing>::BaseField> for PairingVerification<I, IV>
where
    I: Pairing,
    IV: PairingVar<I>,
    IV::G1Var: CurveVar<I::G1, I::BaseField>,
{
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<<I as Pairing>::BaseField>,
    ) -> Result<(), SynthesisError> {
        let coeffs: Vec<_> = 
        self.pubs.unwrap()
            .into_iter()
            .map(|coeff| {
                let pvar = IV::G1Var::new_variable(
                    ark_relations::ns!(cs, "generate_p1"),
                    || Ok(coeff),
                    AllocationMode::Witness,
                ).unwrap();
                Ok(pvar)
            })
            .collect::<Result<Vec<_>, _>>()?;
       // let a_var = IV::G1Var::new_input(cs.clone(), || Ok(self.a.unwrap()))?;

       // let b_var = IV::G1Var::new_input(cs.clone(), || Ok(self.b.unwrap()))?;

        let result_var = IV::G1Var::new_witness(cs.clone(), || Ok(self.result.unwrap()))?;
        let result = coeffs[0].clone() + coeffs[1].clone();

        result_var.enforce_equal(&result)?;
        Ok(())
    }
}
#[cfg(test)]
mod tests {

    use ark_bls12_377::{constraints::PairingVar as IV, constraints::*, Bls12_377 as I};

    use super::*;
    use ark_ec::bls12::Bls12;
    use ark_relations::r1cs::ConstraintSystem;
    use ark_std::rand::{distributions::Uniform, Rng};

    #[test]
    fn preimage_constraints_correctness() {
        let cs =
            ConstraintSystem::<<Bls12<ark_bls12_377::Config> as Pairing>::BaseField>::new_ref();
        let mut rng = ark_std::test_rng();

        PairingVerification::<I, IV>::new(&mut rng)
            .generate_constraints(cs.clone())
            .unwrap();

        assert!(cs.is_satisfied().unwrap());
    }
}
mod test_groth {

    use super::*;
    use ark_bls12_377::G2Projective;
    use ark_bls12_377::{constraints::PairingVar as IV, constraints::*, Bls12_377 as I};
    use ark_bls12_377::{g1, g2, Bls12_377, Config, Fq, Fr};
    use ark_bw6_761::BW6_761 as P;
    use ark_crypto_primitives::snark::CircuitSpecificSetupSNARK;
    use ark_crypto_primitives::snark::SNARK;
    use ark_ec::bls12::Bls12;
    use ark_ff::ToConstraintField;
    use ark_groth16::prepare_verifying_key;
    use ark_groth16::Groth16;
    use ark_r1cs_std::fields::nonnative::params;
    use ark_relations::r1cs::ConstraintSystem;
    use ark_std::rand::{distributions::Uniform, Rng};
    use rand_core::OsRng;
    use rand_core::SeedableRng;
    #[test]
    fn prova() {
        let mut rng = ark_std::test_rng();
        let circuit = PairingVerification::<I, IV>::new(&mut rng);
        let mut rng2 = rand_chacha::ChaChaRng::seed_from_u64(1776);
        let (pk, vk) = Groth16::<P>::circuit_specific_setup(circuit.clone(), &mut rng2).unwrap();
        let proof = Groth16::<P>::prove(&pk, circuit.clone(), &mut OsRng).unwrap();
        
        let inputs = circuit.clone()
            .pubs.unwrap()
            .iter()
            .flat_map(|p| p.to_field_elements().unwrap())
            .collect::<Vec<_>>();
        
        let ok = Groth16::<P>::verify(&pk.vk, &[], &proof).unwrap();
        assert!(ok);
    }
    #[test]
    fn test_prove_and_verify2() {
        // let mut rng = ark_std::test_rng();
        // let mut rng2 = rand_chacha::ChaChaRng::seed_from_u64(1776);
        // let circuit = PairingVerification::<I, IV>::new(&mut rng);
        // let params =
        //     Groth16::<P>::generate_random_parameters_with_reduction(circuit.clone(), &mut rng2)
        //         .unwrap();
        // let pvk = prepare_verifying_key(&params.vk);
        // let proof =
        //     Groth16::<P>::create_random_proof_with_reduction(circuit.clone(), &params, &mut rng)
        //         .unwrap();
        // let public_inputs = circuit
        //     .clone()
        //     .result
        //     .iter()
        //     .flat_map(|p| p.to_field_elements().unwrap())
        //     .collect::<Vec<_>>();
        // assert!(Groth16::<P>::verify_proof(&pvk, &proof, &public_inputs).unwrap());
    }
}
