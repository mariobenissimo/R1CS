use ark_ec::pairing::Pairing;
use ark_r1cs_std::fields::fp::{FpVar};
use ark_r1cs_std::{prelude::*};
use ark_relations::{
    ns,
    r1cs::{ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef, SynthesisError},
  };
use ark_std::marker::PhantomData;

#[derive(Clone)]
struct KeyVerification<I,IV>
where
I: Pairing,
IV: PairingVar<I>,
{
    x: I::ScalarField,
    y: I::G1,
    _iv: PhantomData<IV>,
    _i: PhantomData<I>,
}

impl<I,IV> ConstraintSynthesizer<I::ScalarField> for KeyVerification<I,IV>
where
I: Pairing,
IV: PairingVar<I>,
{
    fn generate_constraints(self, cs: ConstraintSystemRef<I::ScalarField>) -> Result<(), SynthesisError> {
        let a: FpVar<<I as Pairing>::ScalarField> = FpVar::new_witness(cs, || Ok(self.x))?;
        //ERROR HERE
        //the trait bound `<IV as ark_r1cs_std::pairing::PairingVar<I>>::G1Var: ark_r1cs_std::alloc::AllocVar<_, <I as Pairing>::ScalarField>` is not satisfied
        let b = IV::G1Var::new_witness(cs, || Ok(self.y))?;

        Ok(())
    }
  }
