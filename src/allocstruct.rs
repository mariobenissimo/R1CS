use ark_bls12_377::G1Affine;
// Proving i know at and bt which mul performs CT
// AT BT = witness
// CT = input
use ark_ec::AffineRepr;
use ark_ec::{
    pairing::{Pairing, PairingOutput},
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
use rayon::result;
use std::{
    borrow::Borrow,
    ops::{Mul, MulAssign},
};

// e(aG,bH)

pub struct Generators<E: Pairing, IV: PairingVar<E>> {

    pub g: E::G1Affine,

    pub h: E::G2Affine,


    _iv: PhantomData<IV>,
}
pub struct Scalars<E: Pairing, IV: PairingVar<E>> {

    pub a: E::ScalarField,

    pub b: E::ScalarField,

    _iv: PhantomData<IV>,
}

pub struct Global<E: Pairing, IV: PairingVar<E>> {

    pub gens: Generators<E,IV>,
    pub scals: Scalars<E,IV>,
    pub result: E::TargetField,
}

impl<E, IV> Clone for Generators<E, IV>
where
    E: Pairing,
    IV: PairingVar<E>,
{
    fn clone(&self) -> Self {
        Self {
            g: self.g,
            h: self.h,
            _iv: self._iv,
        }
    }
}
impl<E, IV> Generators<E,IV>
where
    E: Pairing,
    IV: PairingVar<E>,
    IV::G1Var: CurveVar<E::G1, E::BaseField>,
    IV::G2Var: CurveVar<E::G2, E::BaseField>,
    IV::GTVar: FieldVar<E::TargetField, E::BaseField>,
{
    fn ver_alloc_var(
        &self,
        cs: ConstraintSystemRef<<E as Pairing>::BaseField>,
        mode: AllocationMode,
    ) -> Result<(IV::G1Var, IV::G2Var), SynthesisError> {
        let c1 = IV::G1Var::new_variable(cs.clone() ,|| Ok(self.g) , mode)?;
        let c2 = IV::G2Var::new_variable(cs.clone(), || Ok(self.h) , mode)?;
        Ok((c1,c2))
    }
}
impl<E, IV> Scalars<E,IV>
where
    E: Pairing,
    IV: PairingVar<E>,
{
    fn ver_alloc_var(
        &self,
        cs: ConstraintSystemRef<<E as Pairing>::BaseField>,
        mode: AllocationMode,
    ) -> Result<(FpVar<E::BaseField>, FpVar<E::BaseField>,), SynthesisError> {
        let scalar_in_fq = &E::BaseField::from_bigint(<E::BaseField as PrimeField>::BigInt::from_bits_le(self.a.into_bigint().to_bits_le().as_slice())).unwrap();
        let a_var = FpVar::new_variable(cs.clone(), || Ok(scalar_in_fq), mode)?;
        let scalar_in_fq = &E::BaseField::from_bigint(<E::BaseField as PrimeField>::BigInt::from_bits_le(self.b.into_bigint().to_bits_le().as_slice())).unwrap();
        let b_var = FpVar::new_variable(cs.clone(), || Ok(scalar_in_fq), mode)?;
        Ok((a_var,b_var))
    }
}
impl<E, IV> Clone for Scalars<E, IV>
where
    E: Pairing,
    IV: PairingVar<E>,
{
    fn clone(&self) -> Self {
        Self {
            a: self.a,
            b: self.b,
            _iv: self._iv,
        }
    }
}
impl<E, IV> Clone for Global<E, IV>
where
    E: Pairing,
    IV: PairingVar<E>,
{
    fn clone(&self) -> Self {
        Self {
            gens: self.gens.clone(),
            scals: self.scals.clone(),
            result: self.result,
        }
    }
}
impl<E, IV> Global<E, IV>
where
    E: Pairing,
    IV: PairingVar<E>,
{
    #[allow(dead_code)]
    pub fn new<R: Rng>(mut rng: R) -> Self {

        let g = E::G1Affine::rand(&mut rng);
        let h = E::G2Affine::rand(&mut rng);
        let gens: Generators<E, IV> = Generators::<E,IV>{
            g,
            h,
            _iv: PhantomData,
        };
        let a = E::ScalarField::rand(&mut rng);
        let b = E::ScalarField::rand(&mut rng);
        let scals = Scalars::<E,IV>{
            a,
            b,
            _iv: PhantomData,
        };
        let ag = g.mul(a);
        let bh = h.mul(b);
        let result = E::pairing(ag,bh);
        Self {
            gens,
            scals,
            result: result.0,
        }
    }
}
impl<I, IV> ConstraintSynthesizer<<I as Pairing>::BaseField> for Global<I, IV>
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
        let (g_var,h_var) = self.gens.ver_alloc_var(cs.clone(), AllocationMode::Witness).unwrap();
        let (a_var,b_var) = self.scals.ver_alloc_var(cs.clone(), AllocationMode::Witness).unwrap();
        let res_var = IV::GTVar::new_input(cs.clone(), || Ok(self.result)).unwrap();
        let bits_a = a_var.to_bits_le()?;
        let ag_var = g_var.scalar_mul_le(bits_a.iter())?;
        let bits_b = b_var.to_bits_le()?;
        let bh_var = h_var.scalar_mul_le(bits_b.iter())?;
        let ag_var_prep = IV::prepare_g1(&ag_var).unwrap();
        let bh_var_prep = IV::prepare_g2(&bh_var).unwrap();
        let result = IV::pairing(ag_var_prep,bh_var_prep).unwrap();
        res_var.enforce_equal(&result);
        Ok(())
    }
}

#[cfg(test)]
mod tests {

    use ark_bls12_377::{constraints::PairingVar as IV, Bls12_377 as I};

    use super::*;
    use ark_ec::bls12::Bls12;
    use ark_relations::r1cs::ConstraintSystem;

    #[test]
    fn preimage_constraints_correctness() {
        let cs =
            ConstraintSystem::<<Bls12<ark_bls12_377::Config> as Pairing>::BaseField>::new_ref();
        let mut rng = ark_std::test_rng();
        Global::<I, IV>::new(&mut rng)
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
    fn test_prove_and_verify() {
        let mut rng = ark_std::test_rng();
        let circuit = Global::<I, IV>::new(&mut rng);
        let mut rng2 = rand_chacha::ChaChaRng::seed_from_u64(1776);
        let (pk, vk) = Groth16::<P>::circuit_specific_setup(circuit.clone(), &mut rng2).unwrap();
        let proof = Groth16::<P>::prove(&pk, circuit.clone(), &mut OsRng).unwrap();
        let public_inputs = circuit.clone().result.to_field_elements().unwrap();
        let ok = Groth16::<P>::verify(&pk.vk, &public_inputs, &proof).unwrap();
        assert!(ok);
    }
    // #[test]
    // fn test_prove_and_verify2() {
    //     let mut rng = ark_std::test_rng();
    //     let mut rng2 = rand_chacha::ChaChaRng::seed_from_u64(1776);
    //     let circuit = AddVerification::<I, IV>::new(&mut rng);
    //     let params =
    //         Groth16::<P>::generate_random_parameters_with_reduction(circuit.clone(), &mut rng2)
    //             .unwrap();
    //     let pvk = prepare_verifying_key(&params.vk);
    //     let proof =
    //         Groth16::<P>::create_random_proof_with_reduction(circuit.clone(), &params, &mut rng)
    //             .unwrap();
    //     let public_inputs = circuit.clone().ct.unwrap().to_field_elements();
    //     assert!(Groth16::<P>::verify_proof(&pvk, &proof, &public_inputs.unwrap()).unwrap());
    // }
}
