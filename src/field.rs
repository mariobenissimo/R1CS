use ark_bls12_377::Fr;
use ark_ff::{Field, PrimeField};
use ark_r1cs_std::{
    boolean,
    fields::fp::FpVar,
    prelude::{AllocVar, EqGadget},
};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_std::{One, UniformRand};

#[derive(Clone, Copy, Debug)]
enum Op {
    Add,
    Mul,
    Sub,
}
#[derive(Clone, Copy, Debug)]
struct AddStruct<F: PrimeField> {
    x: F,
    y: F,
    result: F,
    op: Op,
}
impl<F: PrimeField> AddStruct<F> {
    fn new(op: Op) -> Self {
        let mut rng = ark_std::test_rng();
        let x = F::rand(&mut rng);
        let y = F::rand(&mut rng);
        let mut result = F::one();
        match op {
            Op::Add => {
                result = x + y;
            }
            Op::Mul => {
                result = x * y;
            }
            Op::Sub => {
                result = x - y;
            }
        }
        Self { x, y, result, op }
    }
}
impl<F: PrimeField> ConstraintSynthesizer<F> for AddStruct<F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        let x_var = FpVar::<F>::new_witness(cs.clone(), || Ok(self.x))?;
        let y_var = FpVar::<F>::new_witness(cs.clone(), || Ok(self.y))?;
        let result_var = FpVar::<F>::new_input(cs.clone(), || Ok(self.result))?;
        let mut result = &x_var + &y_var; // way to inizialize Fpvar
        match self.op {
            Op::Add => {
                result = x_var + y_var;
            }
            Op::Mul => {
                result = x_var * y_var;
            }
            Op::Sub => {
                result = x_var - y_var;
            }
        }
        result_var.conditional_enforce_equal(&result, &boolean::Boolean::TRUE)?;
        Ok(())
    }
}

mod tests {
    use super::*;
    use ark_bls12_377::{Fq, Fr};

    use ark_bls12_377::constraints::FqVar;
    use ark_crypto_primitives::snark::SNARK;
    use ark_ec::bls12::Bls12Config;
    use ark_ff::{Field, PrimeField};
    use ark_groth16::Groth16;
    use ark_relations::r1cs::ConstraintSystem;
    use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
    use ark_std::{One, UniformRand};
    use ark_test_curves::bls12::Bls12;
    use ark_test_curves::bls12_381::Bls12_381;
    use ark_test_curves::pairing::Pairing;
    use rand_core::{OsRng, SeedableRng};
    #[test]
    fn preimage_constraints_correctness() {
        for mode in vec![Op::Add, Op::Mul, Op::Sub].into_iter() {
            let cs = ConstraintSystem::<Fr>::new_ref();
            AddStruct::new(mode.clone())
                .generate_constraints(cs.clone())
                .unwrap();
            assert!(cs.is_satisfied().unwrap());
        }
    }
    #[test]
    fn test_with_groth() {
        let mut rng = ark_std::test_rng();
        let a = Fr::rand(&mut rng);
        let b = Fr::rand(&mut rng);

        let c = a + b;

        let circuit = AddStruct {
            x: a,
            y: b,
            result: c,
            op: Op::Add,
        };
        let mut rng2 = rand_chacha::ChaChaRng::seed_from_u64(1776);
        let (pk, vk) =
            Groth16::<ark_bls12_377::Bls12_377>::circuit_specific_setup(circuit, &mut rng2)
                .unwrap();

        let proof = Groth16::<ark_bls12_377::Bls12_377>::prove(&pk, circuit, &mut OsRng).unwrap();

        let public_inputs = vec![circuit.result];
        let ok =
            Groth16::<ark_bls12_377::Bls12_377>::verify(&pk.vk, &public_inputs, &proof).unwrap();
        assert!(ok);
    }
}
