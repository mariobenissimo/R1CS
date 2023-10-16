// proving i know z which perfoms Z = e(cX, Y)
// Z = public input
// c X Y = witness

use ark_ec::pairing::Pairing;
use ark_ff::BigInteger;
use ark_ff::PrimeField;
use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_std::{
    marker::PhantomData,
    rand::Rng,
    UniformRand,
};
use std::ops::Mul;
use ark_r1cs_std::fields::fp::FpVar;

#[derive(Copy)]
struct PairingScalar<I, IV>
where
    I: Pairing,
    IV: PairingVar<I>,
{   
    z: Option<I::TargetField>,
    x: Option<I::G1>,
    y: Option<I::G2>,
    c: Option<I::ScalarField>,
    _iv: Option<PhantomData<IV>>,
    _i: Option<PhantomData<I>>,
}

impl<I, IV> PairingScalar<I, IV>
where
    I: Pairing,
    IV: PairingVar<I>,
{
    #[allow(dead_code)]
    pub fn new<R: Rng>(mut rng: R) -> Self {

        let x = I::G1::rand(&mut rng);
        let y = I::G2::rand(&mut rng);
        
        let c = I::ScalarField::rand(&mut rng);

        let c_x = x.mul(c);

        let ml = I::miller_loop(c_x, y);
        let z = I::final_exponentiation(ml).unwrap();

        Self {
            z: Some(z.0), //targetfield= pairingOutput.0
            x: Some(x),
            y: Some(y),
            c: Some(c),
            _iv: Some(PhantomData),
            _i: Some(PhantomData),
        }
    }
}

impl<I, IV> Clone for PairingScalar<I, IV>
where
    I: Pairing,
    IV: PairingVar<I>,
{
    fn clone(&self) -> Self {
        Self {
            z: self.z,
            x: self.x,
            y: self.y,
            c: self.c,
            _iv: self._iv,
            _i: self._i,
        }
    }
}

impl<I, IV> ConstraintSynthesizer<<I as Pairing>::BaseField> for PairingScalar<I, IV>
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
        //Z = (cX, Y)
        let x_var = IV::G1Var::new_witness(cs.clone(), || Ok(self.x.unwrap()))?;
        let y_var = IV::G2Var::new_witness(cs.clone(), || Ok(self.y.unwrap()))?;

        let scalar_in_fq = &I::BaseField::from_bigint(<I::BaseField as PrimeField>::BigInt::from_bits_le(self.c.unwrap().into_bigint().to_bits_le().as_slice())).unwrap();
        let c_var = FpVar::new_witness(cs.clone(), || Ok(scalar_in_fq))?;
       
        let bits_c = c_var.to_bits_le()?;

        let c_x_var = x_var.scalar_mul_le(bits_c.iter())?;
        
        let z_var = IV::GTVar::new_input(cs.clone(), || Ok(self.z.unwrap()))?;

        let c_x_prepared = IV::prepare_g1(&c_x_var)?;

        let y_prepared = IV::prepare_g2(&y_var)?;

        let z_calc = IV::pairing(c_x_prepared, y_prepared)?;
        
        z_var.enforce_equal(&z_calc)?;

        Ok(())
    }
}

mod test_groth {

    use super::*;
    use ark_bls12_377::{constraints::PairingVar as IV, constraints::*, Bls12_377 as I};
    use ark_bls12_377::{g1, g2, Bls12_377, Config, Fq, Fr};
    use ark_bw6_761::BW6_761 as P;
    use ark_crypto_primitives::snark::CircuitSpecificSetupSNARK;
    use ark_crypto_primitives::snark::SNARK;
    use ark_ec::bls12::Bls12;
    use ark_ff::ToConstraintField;
    use ark_groth16::prepare_verifying_key;
    use ark_groth16::Groth16;
    use ark_std::rand::distributions::Uniform;
    use rand_core::OsRng;
    use rand_core::SeedableRng;
    #[test]
    fn test_prove_and_verify() {
        let mut rng = ark_std::test_rng();
        let circuit = PairingScalar::<I, IV>::new(&mut rng);
        let mut rng2 = rand_chacha::ChaChaRng::seed_from_u64(1776);
        let (pk, vk) = Groth16::<P>::circuit_specific_setup(circuit.clone(), &mut rng2).unwrap();
        let proof = Groth16::<P>::prove(&pk, circuit.clone(), &mut OsRng).unwrap();
        let public_inputs = circuit.clone().z.unwrap().to_field_elements().unwrap();
        let ok = Groth16::<P>::verify(&pk.vk, &public_inputs, &proof).unwrap();
        assert!(ok);
    }
    #[test]
    fn test_prove_and_verify2() {
        let mut rng = ark_std::test_rng();
        let mut rng2 = rand_chacha::ChaChaRng::seed_from_u64(1776);
        let circuit = PairingScalar::<I, IV>::new(&mut rng);
        let params = Groth16::<P>::generate_random_parameters_with_reduction(circuit.clone(), &mut rng2).unwrap();
        let pvk = prepare_verifying_key(&params.vk);
        let proof = Groth16::<P>::create_random_proof_with_reduction(circuit.clone(), &params, &mut rng).unwrap();
        let public_inputs = circuit.clone().z.unwrap().to_field_elements().unwrap();
        assert!(Groth16::<P>::verify_proof(&pvk, &proof, &public_inputs).unwrap());
    }
}