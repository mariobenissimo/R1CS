use ark_bls12_377::Fr;
use ark_ff::{Field, PrimeField};
// We'll use a field associated with the BLS12-381 pairing-friendly
// group for this example.

use ark_r1cs_std::{fields::{fp::FpVar, nonnative::NonNativeFieldVar}, prelude::{AllocVar, EqGadget}, boolean};
// `ark-std` is a utility crate that enables `arkworks` libraries
// to easily support `std` and `no_std` workloads, and also re-exports
// useful crates that should be common across the entire ecosystem, such as `rand`.
use ark_std::{One, UniformRand};
use rayon::result;
use std::marker::PhantomData;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};

// #[derive(Clone, Copy, Debug)]
// struct AddStruct<TargetField: PrimeField, BaseField: PrimeField>
// {
//     x: TargetField,
//     y: TargetField,
//     result: TargetField,
//     _f1: PhantomData<TargetField>,
//     _f2: PhantomData<BaseField>,
// }
// //<Bls12<Config> as Pairing>::ScalarField, <Bls12<Config> as Pairing>::BaseField
// impl<TargetField: PrimeField, BaseField: PrimeField> ConstraintSynthesizer<BaseField> for AddStruct<TargetField,BaseField>
// {
//     fn generate_constraints(
//         self,
//         cs: ConstraintSystemRef<BaseField>,
//     ) -> Result<(), SynthesisError> {

//         let x_var = NonNativeFieldVar::<TargetField,BaseField>::new_witness( cs.clone(),|| Ok(self.x))?;
//         let y_var =  NonNativeFieldVar::<TargetField,BaseField>::new_witness(cs.clone(), || Ok(self.y))?;
//         let result_var = NonNativeFieldVar::<TargetField,BaseField>::new_input(cs.clone(), || Ok(self.result))?;
//         let result = x_var + y_var;
//         result_var.conditional_enforce_equal(&result, &boolean::Boolean::TRUE)?;
//         Ok(())
//     }
// }

#[derive(Clone, Copy, Debug)]
enum Op {
    Add,
    Mul,
    Sub,
}
#[derive(Clone, Copy, Debug)]
struct KeyVerification2<F: PrimeField>{
    x: F,
    y: F,
    result: F,
    op: Op,
}
impl<F: PrimeField> KeyVerification2<F> {
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
        Self {
            x,
            y,
            result,
            op,
        }
    }
}
impl<F: PrimeField> ConstraintSynthesizer<F> for KeyVerification2<F>
{
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<F>,
    ) -> Result<(), SynthesisError> {

        let x_var = FpVar::<F>::new_witness( cs.clone(),|| Ok(self.x))?;
        let y_var =  FpVar::<F>::new_witness(cs.clone(), || Ok(self.y))?;
        let result_var = FpVar::<F>::new_input(cs.clone(), || Ok(self.result))?;
        let mut result= &x_var + &y_var;
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
fn sumFr(){
    // Call the function from new_source.rs
    let mut rng = ark_std::test_rng();
    // Let's sample uniformly random field elements:
    let a = Fr::rand(&mut rng);
    let b = Fr::rand(&mut rng);

    // We can perform all the operations from the `AdditiveGroup` trait:
    // We can add...
    let c = a + b;
    // ... subtract ...
    let d = a - b;
    // ... double elements ...
    assert_eq!(c + d, a.double());

    // ... multiply ...
    let e = c * d;
    // ... square elements ...
    assert_eq!(e, a.square() - b.square());

    // ... and compute inverses ...
    assert_eq!(a.inverse().unwrap() * a, Fr::one()); // have to to unwrap, as `a` could be zero.
}
fn main() {
    sumFr();
}

mod tests{
    use super::*;
    use ark_bls12_377::{Fr, Fq};

    use ark_crypto_primitives::snark::SNARK;
    use ark_ec::bls12::Bls12Config;
    use ark_ff::{Field, PrimeField};
    use ark_std::{One, UniformRand};
    use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
    use ark_relations::r1cs::ConstraintSystem;
    use ark_groth16::Groth16;
    use ark_test_curves::bls12_381::Bls12_381;
    use rand_core::{OsRng, SeedableRng};
    use ark_test_curves::pairing::Pairing;
    use ark_bls12_377::constraints::FqVar;
    use ark_test_curves::bls12::Bls12;
    #[test]
    fn preimage_constraints_correctness() {
        for mode in vec![Op::Add, Op::Mul, Op::Sub].into_iter() {
            let cs = ConstraintSystem::<Fr>::new_ref();
            KeyVerification2::new(mode.clone())
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

        let circuit = KeyVerification2 {
            x : a,
            y: b,
            result: c,
            op: Op::Add,
        };
        let mut rng2 = rand_chacha::ChaChaRng::seed_from_u64(1776);
        let (pk,vk) = Groth16::<ark_bls12_377::Bls12_377>::circuit_specific_setup(circuit, &mut rng2).unwrap();


        let proof = Groth16::<ark_bls12_377::Bls12_377>::prove(&pk, circuit, &mut OsRng).unwrap();

        let public_inputs = vec![circuit.result];
        let ok = Groth16::<ark_bls12_377::Bls12_377>::verify(&pk.vk, &public_inputs, &proof).unwrap();
        assert!(ok);
    }

    // #[test]
    // fn preimage_constraints_correctness2() {
    //     let mut rng = ark_std::test_rng();
    //     let a = ark_bls12_377::Fr::rand(&mut rng);
    //     let b = ark_bls12_377::Fr::rand(&mut rng);

    //     let c = a + b;

    //     let circuit = AddStruct::<ark_bls12_377::Fr, ark_bls12_381::Fr>{
    //         x : a,
    //         y: b,
    //         result: c,
    //         _f1: PhantomData,
    //         _f2: PhantomData,
    //     };
    //     let cs = ConstraintSystem::<ark_bls12_381::Fr>::new_ref();
    //     circuit.generate_constraints(cs.clone()).unwrap();
    //     assert!(cs.is_satisfied().unwrap());
    // }

    // #[test] 
    // fn test_with_groth2 () 
    // {
    //     // type Fr = ark_bls12_377::constraints:
    //     // type Fq= <Bls12<ark_bls12_377::Config> as Pairing>::BaseField;

    //     let mut rng = ark_std::test_rng();
    //     let a = ark_bls12_377::Fr::rand(&mut rng);
    //     let b = ark_bls12_377::Fr::rand(&mut rng);

    //     let c = a + b;

    //     let circuit = AddStruct::<ark_bls12_377::Fr,ark_bls12_377::Fq>{
    //         x : a,
    //         y: b,
    //         result: c,
    //         _f1: PhantomData,
    //         _f2: PhantomData,
    //     };
    //     let mut rng2 = rand_chacha::ChaChaRng::seed_from_u64(1776);
    //     let (pk,vk) = Groth16::<>::circuit_specific_setup(circuit, &mut rng2).unwrap();


    //     let proof = Groth16::<ark_bls12_381::Bls12_381>::create_random_proof_with_reduction(circuit, &pk , &mut rng).unwrap();

    //     let public_inputs = vec![circuit.result];
    //     let ok = Groth16::<ark_bls12_381::Bls12_381>::verify(&pk.vk, &public_inputs, &proof).unwrap();
    //     assert!(ok);

    // }
}

