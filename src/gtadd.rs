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
use std::{
    borrow::Borrow,
    ops::{Mul, MulAssign},
};

#[derive(Copy)]
struct AddVerification<I, IV>
where
    I: Pairing,
    IV: PairingVar<I>,
{
    at: Option<PairingOutput<I>>,
    bt: Option<PairingOutput<I>>,
    ct: Option<I::TargetField>,
    _iv: Option<PhantomData<IV>>,
    _i: Option<PhantomData<I>>,
}
impl<I, IV> Clone for AddVerification<I, IV>
where
    I: Pairing,
    IV: PairingVar<I>,
{
    fn clone(&self) -> Self {
        Self {
            at: self.at,
            bt: self.bt,
            ct: self.ct,
            _iv: self._iv,
            _i: self._i,
        }
    }
}

impl<I, IV> AddVerification<I, IV>
where
    I: Pairing,
    IV: PairingVar<I>,
{
    #[allow(dead_code)]
    pub fn new<R: Rng>(mut rng: R) -> Self {
        // AT = e(aG,G)
        // BT = e(bG,G)
        // CT = AT * BT = e(G,G) ^ {a+b}

        let a: <I as Pairing>::ScalarField = I::ScalarField::rand(&mut rng);
        let b = I::ScalarField::rand(&mut rng);
        let c = a + b;
        let ag = I::G1Affine::generator();
        let bg = I::G1Affine::generator();
        let cg = I::G1Affine::generator();

        let ag2 = ag.mul(a); //aG
        let bg2 = bg.mul(b); //bG
        let cg2 = cg.mul(c); //cG -> (a+b)G

        let at = I::pairing(ag2, I::G2Affine::generator()); // AT = e(aG,G) -> GT

        let bt = I::pairing(bg2, I::G2Affine::generator()); // BT = e(bG,G) -> GT

        let abt = I::pairing(cg2, I::G2Affine::generator()); // ABT = e(cG,G) -> GT => e({a+b}G,G) -> GT

        let t = I::pairing(I::G1Affine::generator(), I::G2Affine::generator()); // T = e(G,G)
        let ct = t.0.pow(&c.into_bigint());
        // CT = e(G,G) ^ c = e(G,G)^{a+b} = GT^a * GT^b
        let ct2 = t.0.pow(&a.into_bigint()) * t.0.pow(&b.into_bigint());
        assert_eq!(ct, ct2);
        // e(G,G)^{a+b}   ==== e(G^{a+b},G)
        assert_eq!(abt.0, ct);

        // at = e(aG,G) / bt = e(bG,G)
        // at * bt = e(aG,G) * e(bG,G)
        // CT = e(G,G) ^ c = e(G,G)^{a+b} = GT^a * GT^b

        Self {
            at: Some(at),
            bt: Some(bt),
            ct: Some(ct),
            _iv: Some(PhantomData),
            _i: Some(PhantomData),
        }
    }
}
impl<I, IV> ConstraintSynthesizer<<I as Pairing>::BaseField> for AddVerification<I, IV>
where
    I: Pairing,
    IV: PairingVar<I>,
    IV::GTVar: FieldVar<I::TargetField, I::BaseField>,
{
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<<I as Pairing>::BaseField>,
    ) -> Result<(), SynthesisError> {
        let at_var = IV::GTVar::new_witness(cs.clone(), || Ok(self.at.unwrap().0))?;

        let bt_var = IV::GTVar::new_witness(cs.clone(), || Ok(self.bt.unwrap().0))?;

        let ct_var = IV::GTVar::new_input(cs.clone(), || Ok(self.ct.unwrap()))?;

        let c = at_var * bt_var;

        c.enforce_equal(&ct_var);
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
        AddVerification::<I, IV>::new(&mut rng)
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
        let circuit = AddVerification::<I, IV>::new(&mut rng);
        let mut rng2 = rand_chacha::ChaChaRng::seed_from_u64(1776);
        let (pk, vk) = Groth16::<P>::circuit_specific_setup(circuit.clone(), &mut rng2).unwrap();
        let proof = Groth16::<P>::prove(&pk, circuit.clone(), &mut OsRng).unwrap();
        let public_inputs = circuit.clone().ct.unwrap().to_field_elements().unwrap();
        let ok = Groth16::<P>::verify(&pk.vk, &public_inputs, &proof).unwrap();
        assert!(ok);
    }
    #[test]
    fn test_prove_and_verify2() {
        let mut rng = ark_std::test_rng();
        let mut rng2 = rand_chacha::ChaChaRng::seed_from_u64(1776);
        let circuit = AddVerification::<I, IV>::new(&mut rng);
        let params =
            Groth16::<P>::generate_random_parameters_with_reduction(circuit.clone(), &mut rng2)
                .unwrap();
        let pvk = prepare_verifying_key(&params.vk);
        let proof =
            Groth16::<P>::create_random_proof_with_reduction(circuit.clone(), &params, &mut rng)
                .unwrap();
        let public_inputs = circuit.clone().ct.unwrap().to_field_elements();
        assert!(Groth16::<P>::verify_proof(&pvk, &proof, &public_inputs.unwrap()).unwrap());
    }
}
