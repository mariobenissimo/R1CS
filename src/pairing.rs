// proving i know A,B which is equals to e(A,B)
// A B = input
// C = witness
use ark_relations::r1cs::ToConstraintField;
use ark_bls12_377::constraints::G1Var;
use ark_ec::AffineRepr;
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

#[derive(Copy)]
struct PublicInput<I>
where
    I: Pairing,
{
    a: Option<I::G1Affine>,
    b: Option<I::G2Affine>,
}
impl<I> Clone for PublicInput<I>
where
    I: Pairing,
{
    fn clone(&self) -> Self {
        Self {
            a: self.a,
            b: self.b,
        }
    }
}
#[derive(Copy)]
struct PairingVerification<I, IV>
where
    I: Pairing,
    IV: PairingVar<I>,
{
    pubs: Option<PublicInput<I>>,
    result: Option<PairingOutput<I>>,
    _iv: Option<PhantomData<IV>>,
}

impl<I, IV> Clone for PairingVerification<I, IV>
where
    I: Pairing,
    IV: PairingVar<I>,
{
    fn clone(&self) -> Self {
        Self {
            pubs: self.pubs,
            result: self.result,
            _iv: self._iv,
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
        let a = I::G1Affine::rand(&mut rng);
        let b = I::G2Affine::rand(&mut rng);
        let ml_result = I::miller_loop(a, b);
        let e2 = I::final_exponentiation(ml_result).unwrap();
        let pubs = PublicInput::<I> {
            a: Some(a),
            b: Some(b),
        };
        Self {
            pubs: Some(pubs),
            result: Some(e2),
            _iv: Some(PhantomData),
        }
    }
}
impl<I, IV> ConstraintSynthesizer<<I as Pairing>::BaseField> for PairingVerification<I, IV>
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
        let a_var = IV::G1Var::new_input(cs.clone(), || Ok(self.pubs.unwrap().a.unwrap()))?;

        let b_var = IV::G2Var::new_input(cs.clone(), || Ok(self.pubs.unwrap().b.unwrap()))?;

        let res_var = IV::GTVar::new_witness(cs.clone(), || Ok(self.result.unwrap().0))?; // here

        let a_pre = IV::prepare_g1(&a_var)?;
        let b_pre = IV::prepare_g2(&b_var)?;
        let result = IV::pairing(a_pre, b_pre)?;
        res_var.enforce_equal(&result)?;
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
        // assert!(cs.num_instance_variables() == 1);
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
    use ark_ff::{ToConstraintField, MontBackend};
    use ark_groth16::prepare_verifying_key;
    use ark_groth16::Groth16;
    use ark_r1cs_std::fields::nonnative::params;
    use ark_relations::r1cs::ConstraintSystem;
    use ark_std::rand::{distributions::Uniform, Rng};
    use rand_core::OsRng;
    use rand_core::SeedableRng;
    use ark_test_curves::short_weierstrass::Projective;
    use ark_crypto_primitives::snark::SNARKGadget;
    use ark_groth16::constraints::Groth16VerifierGadget;
    use ark_std::test_rng;
    use rand_core::RngCore;

    fn pubs_to_field_elements(circuit: PairingVerification<I,IV>) -> Vec<ark_ff::Fp<MontBackend<ark_bls12_377::FqConfig, 6>, 6>> {
        let x = circuit.clone().pubs.unwrap().a.unwrap().x;
        let y = circuit.clone().pubs.unwrap().a.unwrap().y;
        let fp_one = <<Bls12<ark_bls12_377::Config> as Pairing>::BaseField>::ONE;
        let x_c0 = circuit.clone().pubs.unwrap().b.unwrap().x.c0;
        let x_c1 = circuit.clone().pubs.unwrap().b.unwrap().x.c1;
        let y_c0 = circuit.clone().pubs.unwrap().b.unwrap().y.c0;
        let y_c1 = circuit.clone().pubs.unwrap().b.unwrap().y.c1;
        let fp_zero = <<Bls12<ark_bls12_377::Config> as Pairing>::BaseField>::ZERO;
        vec![x,y,fp_one,x_c0,x_c1,y_c0,y_c1,fp_one,fp_zero]
    }
    #[test]
    fn test_prove_and_verify() {
        let mut rng = ark_std::test_rng();
        let circuit = PairingVerification::<I, IV>::new(&mut rng);
        let mut rng2 = rand_chacha::ChaChaRng::seed_from_u64(1776);
        let (opk, ovk) = Groth16::<P>::circuit_specific_setup(circuit.clone(), &mut rng2).unwrap();
        let opvk = Groth16::<P>::process_vk(&ovk).unwrap();
        let public_input = pubs_to_field_elements(circuit.clone());
        let oproof = Groth16::<P>::prove(&opk, circuit, &mut rng2).unwrap();
        assert!(Groth16::<P>::verify_proof(&opvk, &oproof, &public_input).unwrap()); 
    }
}
