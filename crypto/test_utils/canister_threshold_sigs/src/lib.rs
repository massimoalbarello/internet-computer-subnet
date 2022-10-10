//! Utilities for testing IDkg and canister threshold signature operations.

use ic_crypto::utils::TempCryptoComponent;
use ic_crypto_internal_threshold_sig_ecdsa::test_utils::corrupt_dealing;
use ic_crypto_internal_threshold_sig_ecdsa::{IDkgDealingInternal, Seed};
use ic_interfaces::crypto::{
    BasicSigner, IDkgProtocol, KeyManager, ThresholdEcdsaSigVerifier, ThresholdEcdsaSigner,
};
use ic_registry_client_fake::FakeRegistryClient;
use ic_registry_keys::make_crypto_node_key;
use ic_registry_proto_data_provider::ProtoRegistryDataProvider;
use ic_types::crypto::canister_threshold_sig::idkg::{
    BatchSignedIDkgDealing, IDkgDealing, IDkgMaskedTranscriptOrigin, IDkgReceivers, IDkgTranscript,
    IDkgTranscriptId, IDkgTranscriptOperation, IDkgTranscriptParams, IDkgTranscriptType,
    IDkgUnmaskedTranscriptOrigin, SignedIDkgDealing,
};
use ic_types::crypto::canister_threshold_sig::{ExtendedDerivationPath, PreSignatureQuadruple};
use ic_types::crypto::canister_threshold_sig::{
    ThresholdEcdsaCombinedSignature, ThresholdEcdsaSigInputs,
};
use ic_types::crypto::{AlgorithmId, KeyPurpose};
use ic_types::signature::{BasicSignature, BasicSignatureBatch};
use ic_types::{Height, NodeId, PrincipalId, Randomness, RegistryVersion, SubnetId};
use rand::prelude::*;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

pub fn create_params_for_dealers(
    dealer_set: &BTreeSet<NodeId>,
    operation: IDkgTranscriptOperation,
) -> IDkgTranscriptParams {
    IDkgTranscriptParams::new(
        random_transcript_id(),
        dealer_set.clone(),
        dealer_set.clone(),
        RegistryVersion::from(0),
        AlgorithmId::ThresholdEcdsaSecp256k1,
        operation,
    )
    .expect("Should be able to create IDKG params")
}

pub fn mock_unmasked_transcript_type() -> IDkgTranscriptType {
    IDkgTranscriptType::Unmasked(IDkgUnmaskedTranscriptOrigin::ReshareMasked(
        random_transcript_id(),
    ))
}

pub fn mock_masked_transcript_type() -> IDkgTranscriptType {
    IDkgTranscriptType::Masked(IDkgMaskedTranscriptOrigin::Random)
}

pub fn mock_transcript(
    receivers: Option<BTreeSet<NodeId>>,
    transcript_type: IDkgTranscriptType,
) -> IDkgTranscript {
    let receivers = match receivers {
        Some(receivers) => receivers,
        None => {
            let mut receivers = BTreeSet::new();
            for i in 1..10 {
                receivers.insert(node_id(i));
            }
            receivers
        }
    };

    IDkgTranscript {
        transcript_id: random_transcript_id(),
        receivers: IDkgReceivers::new(receivers).unwrap(),
        registry_version: RegistryVersion::from(314),
        verified_dealings: BTreeMap::new(),
        transcript_type,
        algorithm_id: AlgorithmId::ThresholdEcdsaSecp256k1,
        internal_transcript_raw: vec![],
    }
}

pub fn create_signed_dealing(
    params: &IDkgTranscriptParams,
    crypto_components: &BTreeMap<NodeId, TempCryptoComponent>,
    dealer_id: NodeId,
) -> SignedIDkgDealing {
    let dealer = crypto_for(dealer_id, crypto_components);

    let dealing = dealer.create_dealing(params).unwrap_or_else(|error| {
        panic!(
            "failed to create IDkg dealing for {:?}: {:?}",
            dealer_id, error
        )
    });

    let signature = dealer
        .sign_basic(&dealing, dealer_id, params.registry_version())
        .expect("Failed to sign a dealing");

    SignedIDkgDealing {
        content: dealing,
        signature: BasicSignature {
            signature,
            signer: dealer_id,
        },
    }
}

pub fn create_and_verify_signed_dealing(
    params: &IDkgTranscriptParams,
    crypto_components: &BTreeMap<NodeId, TempCryptoComponent>,
    dealer_id: NodeId,
) -> SignedIDkgDealing {
    let signed_dealing = create_signed_dealing(params, crypto_components, dealer_id);

    let dealer = crypto_for(dealer_id, crypto_components);
    // Verify the dealing is publicly valid
    dealer
        .verify_dealing_public(params, &signed_dealing)
        .expect("unexpectedly invalid dealing");

    // Verify the dealing is privately valid for all receivers
    for receiver in params.receivers().get() {
        crypto_for(*receiver, crypto_components)
            .verify_dealing_private(params, &signed_dealing)
            .expect("unexpectedly invalid dealing (private verification)");
    }

    signed_dealing
}

pub fn create_and_verify_signed_dealings(
    params: &IDkgTranscriptParams,
    crypto_components: &BTreeMap<NodeId, TempCryptoComponent>,
) -> BTreeMap<NodeId, SignedIDkgDealing> {
    params
        .dealers()
        .get()
        .iter()
        .map(|node| {
            let dealing = create_and_verify_signed_dealing(params, crypto_components, *node);
            (*node, dealing)
        })
        .collect()
}

pub fn batch_sign_signed_dealing(
    params: &IDkgTranscriptParams,
    crypto_components: &BTreeMap<NodeId, TempCryptoComponent>,
    signed_dealing: SignedIDkgDealing,
) -> BatchSignedIDkgDealing {
    let signers = params.receivers().get();
    batch_signature_from_signers(
        params.registry_version(),
        crypto_components,
        signed_dealing,
        signers,
    )
}

pub fn batch_signature_from_signers(
    registry_version: RegistryVersion,
    crypto_components: &BTreeMap<NodeId, TempCryptoComponent>,
    signed_dealing: SignedIDkgDealing,
    signers: &BTreeSet<NodeId>,
) -> BatchSignedIDkgDealing {
    let signature = {
        let mut signatures_map = BTreeMap::new();
        for signer in signers {
            let signature = crypto_for(*signer, crypto_components)
                .sign_basic(&signed_dealing, *signer, registry_version)
                .expect("failed to generate basic-signature");
            signatures_map.insert(*signer, signature);
        }

        BasicSignatureBatch { signatures_map }
    };
    BatchSignedIDkgDealing {
        content: signed_dealing,
        signature,
    }
}

pub fn batch_sign_signed_dealings(
    params: &IDkgTranscriptParams,
    crypto_components: &BTreeMap<NodeId, TempCryptoComponent>,
    signed_dealings: BTreeMap<NodeId, SignedIDkgDealing>,
) -> BTreeMap<NodeId, BatchSignedIDkgDealing> {
    signed_dealings
        .into_iter()
        .map(|(dealer_id, signed_dealing)| {
            let multisigned_dealing =
                batch_sign_signed_dealing(params, crypto_components, signed_dealing);

            (dealer_id, multisigned_dealing)
        })
        .collect()
}

pub fn create_transcript(
    params: &IDkgTranscriptParams,
    crypto_components: &BTreeMap<NodeId, TempCryptoComponent>,
    dealings: &BTreeMap<NodeId, BatchSignedIDkgDealing>,
    creator_id: NodeId,
) -> IDkgTranscript {
    crypto_for(creator_id, crypto_components)
        .create_transcript(params, dealings)
        .unwrap_or_else(|error| {
            panic!(
                "failed to create transcript for {:?}: {:?}",
                creator_id, error
            )
        })
}

pub fn load_transcript(
    transcript: &IDkgTranscript,
    crypto_components: &BTreeMap<NodeId, TempCryptoComponent>,
    loader_id: NodeId,
) {
    crypto_for(loader_id, crypto_components)
        .load_transcript(transcript)
        .unwrap_or_else(|error| {
            panic!("failed to load transcript for {:?}: {:?}", loader_id, error)
        });
}

pub fn load_input_transcripts(
    crypto_components: &BTreeMap<NodeId, TempCryptoComponent>,
    loader_id: NodeId,
    inputs: &ThresholdEcdsaSigInputs,
) {
    load_transcript(
        inputs.presig_quadruple().kappa_unmasked(),
        crypto_components,
        loader_id,
    );
    load_transcript(
        inputs.presig_quadruple().lambda_masked(),
        crypto_components,
        loader_id,
    );
    load_transcript(
        inputs.presig_quadruple().kappa_times_lambda(),
        crypto_components,
        loader_id,
    );
    load_transcript(
        inputs.presig_quadruple().key_times_lambda(),
        crypto_components,
        loader_id,
    );
    load_transcript(inputs.key_transcript(), crypto_components, loader_id);
}

pub fn load_previous_transcripts_and_create_signed_dealing(
    params: &IDkgTranscriptParams,
    crypto_components: &BTreeMap<NodeId, TempCryptoComponent>,
    loader_id: NodeId,
) -> SignedIDkgDealing {
    match params.operation_type() {
        IDkgTranscriptOperation::Random => (),
        IDkgTranscriptOperation::ReshareOfMasked(transcript)
        | IDkgTranscriptOperation::ReshareOfUnmasked(transcript) => {
            load_transcript(transcript, crypto_components, loader_id);
        }
        IDkgTranscriptOperation::UnmaskedTimesMasked(transcript_1, transcript_2) => {
            load_transcript(transcript_1, crypto_components, loader_id);
            load_transcript(transcript_2, crypto_components, loader_id);
        }
    }

    create_and_verify_signed_dealing(params, crypto_components, loader_id)
}

pub fn load_previous_transcripts_and_create_signed_dealings(
    params: &IDkgTranscriptParams,
    crypto_components: &BTreeMap<NodeId, TempCryptoComponent>,
) -> BTreeMap<NodeId, SignedIDkgDealing> {
    params
        .dealers()
        .get()
        .iter()
        .map(|node| {
            let signed_dealing = load_previous_transcripts_and_create_signed_dealing(
                params,
                crypto_components,
                *node,
            );
            (*node, signed_dealing)
        })
        .collect()
}

/// Load previous transcripts on each node (if resharing or multiplying),
/// create all dealings, multi-sign them, and build a transcript from those
/// multi-signed dealings.
pub fn run_idkg_and_create_and_verify_transcript(
    params: &IDkgTranscriptParams,
    crypto_components: &BTreeMap<NodeId, TempCryptoComponent>,
) -> IDkgTranscript {
    let dealings = load_previous_transcripts_and_create_signed_dealings(params, crypto_components);
    let multisigned_dealings = batch_sign_signed_dealings(params, crypto_components, dealings);
    let transcript_creator = params.dealers().get().iter().next().unwrap();
    let transcript = create_transcript(
        params,
        crypto_components,
        &multisigned_dealings,
        *transcript_creator,
    );
    assert!(crypto_for(random_receiver_id(params), crypto_components)
        .verify_transcript(params, &transcript)
        .is_ok());
    transcript
}

pub fn generate_key_transcript(
    env: &CanisterThresholdSigTestEnvironment,
    algorithm_id: AlgorithmId,
) -> IDkgTranscript {
    let masked_key_params = env.params_for_random_sharing(algorithm_id);

    let masked_key_transcript =
        run_idkg_and_create_and_verify_transcript(&masked_key_params, &env.crypto_components);

    let unmasked_key_params = build_params_from_previous(
        masked_key_params,
        IDkgTranscriptOperation::ReshareOfMasked(masked_key_transcript),
    );

    run_idkg_and_create_and_verify_transcript(&unmasked_key_params, &env.crypto_components)
}

pub fn generate_presig_quadruple(
    env: &CanisterThresholdSigTestEnvironment,
    algorithm_id: AlgorithmId,
    key_transcript: &IDkgTranscript,
) -> PreSignatureQuadruple {
    let lambda_params = env.params_for_random_sharing(algorithm_id);
    let lambda_transcript =
        run_idkg_and_create_and_verify_transcript(&lambda_params, &env.crypto_components);

    let kappa_transcript = {
        let masked_kappa_params = env.params_for_random_sharing(algorithm_id);

        let masked_kappa_transcript =
            run_idkg_and_create_and_verify_transcript(&masked_kappa_params, &env.crypto_components);

        let unmasked_kappa_params = build_params_from_previous(
            masked_kappa_params,
            IDkgTranscriptOperation::ReshareOfMasked(masked_kappa_transcript),
        );

        run_idkg_and_create_and_verify_transcript(&unmasked_kappa_params, &env.crypto_components)
    };

    let kappa_times_lambda_transcript = {
        let kappa_times_lambda_params = build_params_from_previous(
            lambda_params.clone(),
            IDkgTranscriptOperation::UnmaskedTimesMasked(
                kappa_transcript.clone(),
                lambda_transcript.clone(),
            ),
        );

        run_idkg_and_create_and_verify_transcript(
            &kappa_times_lambda_params,
            &env.crypto_components,
        )
    };

    let key_times_lambda_transcript = {
        let key_times_lambda_params = build_params_from_previous(
            lambda_params,
            IDkgTranscriptOperation::UnmaskedTimesMasked(
                key_transcript.clone(),
                lambda_transcript.clone(),
            ),
        );

        run_idkg_and_create_and_verify_transcript(&key_times_lambda_params, &env.crypto_components)
    };

    PreSignatureQuadruple::new(
        kappa_transcript,
        lambda_transcript,
        kappa_times_lambda_transcript,
        key_times_lambda_transcript,
    )
    .unwrap_or_else(|error| panic!("failed to create pre-signature quadruple: {:?}", error))
}

/// Creates a new `IDkgTranscriptParams` with all information copied from a
/// previous one, except the operation (as given) and the Id
/// (randomly-generated, to avoid collisions).
pub fn build_params_from_previous(
    previous_params: IDkgTranscriptParams,
    operation_type: IDkgTranscriptOperation,
) -> IDkgTranscriptParams {
    IDkgTranscriptParams::new(
        random_transcript_id(),
        previous_params.dealers().get().clone(),
        previous_params.receivers().get().clone(),
        previous_params.registry_version(),
        previous_params.algorithm_id(),
        operation_type,
    )
    .expect("failed to create resharing/multiplication IDkgTranscriptParams")
}

pub struct CanisterThresholdSigTestEnvironment {
    pub crypto_components: BTreeMap<NodeId, TempCryptoComponent>,
    pub registry_data: Arc<ProtoRegistryDataProvider>,
    pub registry: Arc<FakeRegistryClient>,
    pub newest_registry_version: RegistryVersion,
}

impl CanisterThresholdSigTestEnvironment {
    /// Creates a new test environment with the given number of nodes.
    pub fn new(num_of_nodes: usize) -> Self {
        let registry_data = Arc::new(ProtoRegistryDataProvider::new());
        let registry = Arc::new(FakeRegistryClient::new(Arc::clone(&registry_data) as Arc<_>));
        let registry_version = random_registry_version();

        let mut env = Self {
            crypto_components: BTreeMap::new(),
            registry_data,
            registry,
            newest_registry_version: registry_version,
        };

        for node_id in n_random_node_ids(num_of_nodes) {
            env.create_crypto_component_with_sign_mega_and_multisign_keys_in_registry(
                node_id,
                registry_version,
            );
        }
        env.registry.update_to_latest_version();

        env
    }

    /// Returns an `IDkgTranscriptParams` appropriate for creating a random
    /// sharing in this environment.
    pub fn params_for_random_sharing(&self, algorithm_id: AlgorithmId) -> IDkgTranscriptParams {
        let nodes: BTreeSet<NodeId> = self.crypto_components.keys().copied().collect();

        IDkgTranscriptParams::new(
            random_transcript_id(),
            nodes.clone(),
            nodes,
            self.newest_registry_version,
            algorithm_id,
            IDkgTranscriptOperation::Random,
        )
        .expect("failed to create random IDkgTranscriptParams")
    }

    pub fn receivers(&self) -> BTreeSet<NodeId> {
        self.crypto_components.keys().cloned().collect()
    }

    fn create_crypto_component_with_sign_mega_and_multisign_keys_in_registry(
        &mut self,
        node_id: NodeId,
        registry_version: RegistryVersion,
    ) {
        if self.crypto_components.contains_key(&node_id) {
            return;
        }

        let temp_crypto = TempCryptoComponent::builder()
            .with_registry(Arc::clone(&self.registry) as Arc<_>)
            .with_node_id(node_id)
            .with_keys(ic_crypto::utils::NodeKeysToGenerate {
                generate_node_signing_keys: true,
                generate_committee_signing_keys: true,
                generate_dkg_dealing_encryption_keys: false,
                generate_idkg_dealing_encryption_keys: true,
                generate_tls_keys_and_certificate: false,
            })
            .build();
        let node_keys = temp_crypto.node_public_keys();
        self.crypto_components.insert(node_id, temp_crypto);

        self.registry_data
            .add(
                &make_crypto_node_key(node_id, KeyPurpose::NodeSigning),
                registry_version,
                node_keys.node_signing_pk,
            )
            .expect("failed to add committee public key to registry");
        self.registry_data
            .add(
                &make_crypto_node_key(node_id, KeyPurpose::CommitteeSigning),
                registry_version,
                node_keys.committee_signing_pk,
            )
            .expect("failed to add committee public key to registry");

        self.registry_data
            .add(
                &make_crypto_node_key(node_id, KeyPurpose::IDkgMEGaEncryption),
                registry_version,
                node_keys.idkg_dealing_encryption_pk,
            )
            .expect("Could not add MEGa public key to registry");
    }
}

pub fn random_receiver_for_inputs(inputs: &ThresholdEcdsaSigInputs) -> NodeId {
    *inputs
        .receivers()
        .get()
        .iter()
        .choose(&mut thread_rng())
        .expect("receivers is empty")
}

/// Returns a randomly-generate `NodeId` that is *not* in `exclusions`.
pub fn random_node_id_excluding(exclusions: &BTreeSet<NodeId>) -> NodeId {
    *random_node_ids_excluding(exclusions, 1)
        .iter()
        .next()
        .expect("we know this is non-empty")
}

/// Returns `n` randomly-generate `NodeId`s that are *not* in `exclusions`.
pub fn random_node_ids_excluding(exclusions: &BTreeSet<NodeId>, n: usize) -> BTreeSet<NodeId> {
    let rng = &mut thread_rng();
    let mut node_ids = BTreeSet::new();
    while node_ids.len() < n {
        let candidate = node_id(rng.gen());
        if !exclusions.contains(&candidate) {
            node_ids.insert(candidate);
        }
    }
    assert!(node_ids.is_disjoint(exclusions));
    node_ids
}

pub fn node_id(id: u64) -> NodeId {
    NodeId::from(PrincipalId::new_node_test_id(id))
}

pub fn set_of_nodes(ids: &[u64]) -> BTreeSet<NodeId> {
    let mut nodes = BTreeSet::new();
    for id in ids.iter() {
        nodes.insert(node_id(*id));
    }
    nodes
}

fn random_registry_version() -> RegistryVersion {
    RegistryVersion::new(thread_rng().gen_range(1..u32::MAX) as u64)
}

fn random_transcript_id() -> IDkgTranscriptId {
    let mut rng = thread_rng();

    let id = rng.gen::<u64>();
    let subnet = SubnetId::from(PrincipalId::new_subnet_test_id(rng.gen::<u64>()));
    let height = Height::from(rng.gen::<u64>());

    IDkgTranscriptId::new(subnet, id, height)
}

fn n_random_node_ids(n: usize) -> BTreeSet<NodeId> {
    let rng = &mut thread_rng();
    let mut node_ids = BTreeSet::new();
    while node_ids.len() < n {
        node_ids.insert(NodeId::from(PrincipalId::new_node_test_id(rng.gen())));
    }
    node_ids
}

fn crypto_for<T>(node_id: NodeId, crypto_components: &BTreeMap<NodeId, T>) -> &T {
    crypto_components
        .get(&node_id)
        .unwrap_or_else(|| panic!("missing crypto component for {:?}", node_id))
}

pub fn random_receiver_id(params: &IDkgTranscriptParams) -> NodeId {
    *params
        .receivers()
        .get()
        .iter()
        .choose(&mut thread_rng())
        .expect("receivers is empty")
}

pub fn random_receiver_id_excluding(receivers: &IDkgReceivers, exclusion: NodeId) -> NodeId {
    if receivers.get().len() == 1 {
        let (_receiver_idx, receiver_id) = receivers.iter().next().unwrap();
        if receiver_id == exclusion {
            panic!("the only possible receiver is excluded")
        }
    }
    let rng = &mut thread_rng();
    loop {
        let random_receiver_id = *receivers.get().iter().choose(rng).expect("receivers empty");
        if random_receiver_id != exclusion {
            return random_receiver_id;
        }
    }
}

pub fn random_dealer_id(params: &IDkgTranscriptParams) -> NodeId {
    *params
        .dealers()
        .get()
        .iter()
        .choose(&mut thread_rng())
        .expect("dealers is empty")
}

pub fn random_dealer_id_excluding(transcript: &IDkgTranscript, exclusion: NodeId) -> NodeId {
    let mut rng = rand::thread_rng();
    let excluded_index = transcript
        .index_for_dealer_id(exclusion)
        .expect("excluded node not a dealer");
    let dealer_indexes = transcript
        .verified_dealings
        .keys()
        .cloned()
        .filter(|x| x != &excluded_index)
        .collect::<Vec<u32>>();

    let node_index = dealer_indexes.choose(&mut rng).expect("dealing is empty");
    transcript
        .dealer_id_for_index(*node_index)
        .expect("dealer index not in transcript")
}

/// Corrupts the dealing for a single randomly picked receiver.
/// node_id is the self Node Id. The shares for the receivers specified
/// in exclude_receivers won't be corrupted.
/// The transcript params used to create the dealing is passed in with the
/// dealing to be corrupted.
pub fn corrupt_idkg_dealing<R: CryptoRng + RngCore>(
    idkg_dealing: &IDkgDealing,
    transcript_params: &IDkgTranscriptParams,
    exclude_receivers: &BTreeSet<NodeId>,
    rng: &mut R,
) -> Result<IDkgDealing, CorruptIDkgDealingError> {
    let internal_dealing = IDkgDealingInternal::deserialize(&idkg_dealing.internal_dealing_raw)
        .map_err(|e| CorruptIDkgDealingError::SerializationError(format!("{:?}", e)))?;

    let receivers: Vec<_> = transcript_params
        .receivers()
        .get()
        .difference(exclude_receivers)
        .collect();
    if receivers.is_empty() {
        return Err(CorruptIDkgDealingError::NoReceivers);
    }
    let receiver = receivers[rng.gen_range(0..receivers.len())];
    let node_index = transcript_params.receivers().position(*receiver).unwrap();

    let seed = Seed::from_rng(rng);
    let corrupted_dealing = corrupt_dealing(&internal_dealing, &[node_index], seed)
        .map_err(|e| CorruptIDkgDealingError::FailedToCorruptDealing(format!("{:?}", e)))?;
    let internal_dealing_raw = corrupted_dealing
        .serialize()
        .map_err(|e| CorruptIDkgDealingError::SerializationError(format!("{:?}", e)))?;
    Ok(IDkgDealing {
        transcript_id: idkg_dealing.transcript_id,
        internal_dealing_raw,
    })
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CorruptIDkgDealingError {
    SerializationError(String),
    FailedToCorruptDealing(String),
    NoReceivers,
}

pub fn generate_tecdsa_protocol_inputs(
    env: &CanisterThresholdSigTestEnvironment,
    key_transcript: &IDkgTranscript,
    message_hash: &[u8],
    nonce: Randomness,
    derivation_path: ExtendedDerivationPath,
    algorithm_id: AlgorithmId,
) -> ThresholdEcdsaSigInputs {
    let quadruple = generate_presig_quadruple(env, algorithm_id, key_transcript);

    ThresholdEcdsaSigInputs::new(
        &derivation_path,
        message_hash,
        nonce,
        quadruple,
        key_transcript.clone(),
    )
    .expect("failed to create signature inputs")
}

pub fn run_tecdsa_protocol(
    env: &CanisterThresholdSigTestEnvironment,
    sig_inputs: &ThresholdEcdsaSigInputs,
) -> ThresholdEcdsaCombinedSignature {
    let sig_shares: BTreeMap<_, _> = sig_inputs
        .receivers()
        .get()
        .iter()
        .map(|&signer_id| {
            load_input_transcripts(&env.crypto_components, signer_id, sig_inputs);

            let sig_share = crypto_for(signer_id, &env.crypto_components)
                .sign_share(sig_inputs)
                .expect("failed to create sig share");
            (signer_id, sig_share)
        })
        .collect();

    // Verify that each signature share can be verified
    let verifier_id = random_node_id_excluding(sig_inputs.receivers().get());
    let verifier_crypto_component = TempCryptoComponent::builder()
        .with_registry(Arc::clone(&env.registry) as Arc<_>)
        .with_node_id(verifier_id)
        .build();
    for (signer_id, sig_share) in sig_shares.iter() {
        assert!(verifier_crypto_component
            .verify_sig_share(*signer_id, sig_inputs, sig_share)
            .is_ok());
    }

    let combiner_crypto_component = TempCryptoComponent::builder()
        .with_registry(Arc::clone(&env.registry) as Arc<_>)
        .with_node_id(verifier_id)
        .build();
    combiner_crypto_component
        .combine_sig_shares(sig_inputs, &sig_shares)
        .expect("Failed to generate signature")
}
