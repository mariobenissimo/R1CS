use ark_ec::{pairing::{Pairing, PairingOutput}, CurveGroup};

use ark_r1cs_std::prelude::*;
use ark_relations::{
    ns,
    r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError},
};

use ark_std::{
    marker::PhantomData,
    rand::{CryptoRng, Rng},
    UniformRand,
};
use ark_relations::r1cs::Namespace;
use std::borrow::Borrow;

#[derive(Clone)]
struct KeyVerification<I, IV>
where
    I: Pairing,
    IV: PairingVar<I>,
{
    x: I::G1,
    y: I::G2,
    z: PairingOutput<I>,  //Fqk
    _iv: PhantomData<IV>,
    _i: PhantomData<I>,
}

impl<I, IV> KeyVerification<I, IV>
where
    I: Pairing,
    IV: PairingVar<I>,
    IV::G1Var: CurveVar<I::G1, I::BaseField>,
    IV::G2Var: CurveVar<I::G2, I::BaseField>,
    Namespace<<<I as Pairing>::G1 as CurveGroup>::BaseField>: From<ConstraintSystemRef<<I as Pairing>::BaseField>>, //here
    PairingOutput<I>: Borrow<<I as Pairing>::TargetField>
    
    {
    #[allow(dead_code)]
    pub fn new<R: Rng + CryptoRng>(
        mut rng: &mut R,
    ) -> Self {
        let x = I::G1::rand(&mut rng);
        let y = I::G2::rand(&mut rng);
        let x_prep = I::G1Prepared::from(x);
        let y_prep = I::G2Prepared::from(y);
        let z = I::pairing(x_prep, y_prep);

        Self {
            x: x,
            y: y,
            z: z,
            _iv: PhantomData,
            _i: PhantomData,
        }


    }

}
impl<I, IV> ConstraintSynthesizer<<I as Pairing>::BaseField> for KeyVerification<I, IV>
where
    I: Pairing,
    IV: PairingVar<I>,
    IV::G1Var: CurveVar<I::G1, I::BaseField>,
    IV::G2Var: CurveVar<I::G2, I::BaseField>,
    Namespace<<<I as Pairing>::G1 as CurveGroup>::BaseField>: From<ConstraintSystemRef<<I as Pairing>::BaseField>>, //here
    PairingOutput<I>: Borrow<<I as Pairing>::TargetField>

{
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<<I as Pairing>::BaseField>,
    ) -> Result<(), SynthesisError> {
       
        let xvar = IV::G1Var::new_input(cs.clone(), || Ok(self.x))?;
      
        let yvar = IV::G2Var::new_input(cs.clone(), || Ok(self.y))?;

        let exp_res = IV::GTVar::new_input(cs.clone(), || Ok(self.z))?; // here

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
    use ark_bls12_377::{
      constraints::PairingVar as IV, Bls12_377 as I,
      constraints::*,
  };

    use ark_ec::bls12::Bls12;
    use ark_relations::r1cs::ConstraintSystem;
    use super::*;
    #[test]
    fn preimage_constraints_correctness() {
        let mut rng = ark_std::test_rng();
        let cs = ConstraintSystem::<<Bls12<ark_bls12_377::Config> as Pairing>::BaseField>::new_ref();

        KeyVerification::<I, IV>::new(&mut rng).generate_constraints(cs.clone()).unwrap();
        
        assert!(cs.is_satisfied().unwrap());

    }

    }
