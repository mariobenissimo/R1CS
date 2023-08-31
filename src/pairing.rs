use std::ops::{MulAssign, Mul};
use ark_ec::CurveConfig;
use ark_ec::pairing::Pairing;
use ark_ec::{bls12::{G1Projective, Bls12Config}, Group};
use ark_bls12_377::{Fq, Bls12_377, G1Affine};
use ark_r1cs_std::groups::bls12::{G1Var, G1PreparedVar, G1AffineVar};
use ark_r1cs_std::{prelude::*};
use ark_ff::{PrimeField};
use ark_bls12_377::Fr;
use ark_relations::{
    ns,
    r1cs::{ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef, SynthesisError},
  };


#[derive(Clone)]
struct KeyVerification {
    //witness
    x: Fr,

    //public input
    y: G1Projective<ark_bls12_377::Config>,
}
// create a circuit R1CS that build g^x = y

impl ConstraintSynthesizer<Fq> for KeyVerification
{
    fn generate_constraints(self, cs: ConstraintSystemRef<Fq>) -> Result<(), SynthesisError> {
  
        let mut generator = G1Projective::<ark_bls12_377::Config>::generator();

        let mut g_x = generator.mul(self.x);

        // ALLOCATE CIRCUIT VARIABLE

        let y_var = G1Var::<ark_bls12_377::Config>::new_input(cs, || Ok(self.y));
        // let exp_y = 
        //     G1Var::new_input(ns!(cs.clone(), "point"), || Ok(self.y.clone())).unwrap();
  
        // //let x_var = FpVar::new_witness(ns!(cs.clone(), "value"), || Ok(self.x.clone())).unwrap();

        // let multiplied_point = generator.mul(self.x.into_repr());
        
        // println!("{:?}", multiplied_point);

        // let calc_y= 
        //     G1Var::new_witness(ns!(cs.clone(), "point"), || Ok(multiplied_point)).unwrap();

        // calc_y.enforce_equal(&exp_y)?;
  
        Ok(())
    }
  }
