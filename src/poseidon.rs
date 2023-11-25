
#[cfg(test)]
mod tests {
    use ark_ff::UniformRand;
    use ark_r1cs_std::fields::fp::FpVar;
    use ark_r1cs_std::prelude::*;
    use ark_relations::r1cs::ConstraintSystem;
    use ark_relations::*;
    use ark_std::test_rng;
    use ark_ec::bls12::Bls12;
    use ark_ec::pairing::Pairing;
    use ark_crypto_primitives::sponge::poseidon::constraints::PoseidonSpongeVar;
    use ark_crypto_primitives::sponge::poseidon::PoseidonSponge;
    #[test]
    fn absorb_test() {
        let mut rng = test_rng();
        let cs = ConstraintSystem::<<Bls12<ark_bls12_377::Config> as Pairing>::BaseField>::new_ref();

        let absorb1 = ark_bls12_377::g1::G1Affine::rand(&mut rng);
        let absorb1_var = ark_bls12_377::constraints::G1Var::new_input(cs.clone(), || Ok(absorb1));

        // let absorb2: Vec<_> = (0..8).map(|i| vec![i, i + 1, i + 2]).collect();
        // let absorb2_var: Vec<_> = absorb2
        //     .iter()
        //     .map(|v| UInt8::new_input_vec(ns!(cs, "absorb2"), v).unwrap())
        //     .collect();


        let mut native_sponge = PoseidonSponge::<Fr>::new(&sponge_params);
        let mut constraint_sponge = PoseidonSpongeVar::<Fr>::new(cs.clone(), &sponge_params);

        native_sponge.absorb(&absorb1);
        constraint_sponge.absorb(&absorb1_var).unwrap();

        let squeeze1 = native_sponge.squeeze_native_field_elements(1);
        let squeeze2 = constraint_sponge.squeeze_field_elements(1).unwrap();

        assert_eq!(squeeze2.value().unwrap(), squeeze1);
        assert!(cs.is_satisfied().unwrap());

        // native_sponge.absorb(&absorb2);
        // constraint_sponge.absorb(&absorb2_var).unwrap();

        // let squeeze1 = native_sponge.squeeze_native_field_elements(1);
        // let squeeze2 = constraint_sponge.squeeze_field_elements(1).unwrap();

        // assert_eq!(squeeze2.value().unwrap(), squeeze1);
        // assert!(cs.is_satisfied().unwrap());
    }
}
