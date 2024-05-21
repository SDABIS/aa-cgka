use serde_json::Value;
use core_group::create_commit_params::CreateCommitParams;
use openmls_traits::signatures::Signer;

use super::*;
use crate::{messages::group_info::GroupInfo};

impl MlsGroup {
    pub fn add_new_reqs<KeyStore: OpenMlsKeyStore>(
        &mut self,
        provider: &impl OpenMlsProvider<KeyStoreProvider = KeyStore>,
        signer: &impl Signer,
        new_reqs: &[Value],
    ) -> Result<
        (MlsMessageOut, Option<MlsMessageOut>, Option<GroupInfo>),
        AddReqsError<KeyStore::Error>,
    > {
        self.is_operational()?;

        if new_reqs.is_empty() {
            return Err(AddReqsError::EmptyInput(EmptyInputError::AddReqs));
        }

        // Create inline remove proposals
        let mut inline_proposals = Vec::new();
        for req in new_reqs.iter() {
            let serialised_req = serde_json::to_vec(req)
                .map_err(|_| LibraryError::custom("Error serialising"))?.into();
            inline_proposals.push(Proposal::AddReqs(AddReqsProposal { new_req: serialised_req }))
        }

        // Create Commit over all proposals
        // TODO #751
        let params = CreateCommitParams::builder()
            .framing_parameters(self.framing_parameters())
            .proposal_store(&self.proposal_store)
            .inline_proposals(inline_proposals)
            .build();
        let create_commit_result = self.group.create_commit(params, provider, signer)?;

        // Convert PublicMessage messages to MLSMessage and encrypt them if required by
        // the configuration
        let mls_message = self.content_to_mls_message(create_commit_result.commit, provider)?;

        // Set the current group state to [`MlsGroupState::PendingCommit`],
        // storing the current [`StagedCommit`] from the commit results
        self.group_state = MlsGroupState::PendingCommit(Box::new(PendingCommitState::Member(
            create_commit_result.staged_commit,
        )));

        // Since the state of the group might be changed, arm the state flag
        self.flag_state_change();

        Ok((
            mls_message,
            create_commit_result
                .welcome_option
                .map(|w| MlsMessageOut::from_welcome(w, self.group.version())),
            create_commit_result.group_info,
        ))
    }

    pub fn update_reqs<KeyStore: OpenMlsKeyStore>(
        &mut self,
        provider: &impl OpenMlsProvider<KeyStoreProvider = KeyStore>,
        signer: &impl Signer,
        new_req: &Value,
        index: u32
    ) -> Result<
        (MlsMessageOut, Option<MlsMessageOut>, Option<GroupInfo>),
        UpdateReqsError<KeyStore::Error>,
    > {
        self.is_operational()?;

        // Create inline remove proposals
        let mut inline_proposals = Vec::new();
        let serialised_req = serde_json::to_vec(new_req)
            .map_err(|_| LibraryError::custom("Error serialising requirement"))?.into();
        inline_proposals.push(Proposal::UpdateReqs(UpdateReqsProposal { index, new_req: serialised_req }));

        // Create Commit over all proposals
        // TODO #751
        let params = CreateCommitParams::builder()
            .framing_parameters(self.framing_parameters())
            .proposal_store(&self.proposal_store)
            .inline_proposals(inline_proposals)
            .build();
        let create_commit_result = self.group.create_commit(params, provider, signer)?;

        // Convert PublicMessage messages to MLSMessage and encrypt them if required by
        // the configuration
        let mls_message = self.content_to_mls_message(create_commit_result.commit, provider)?;

        // Set the current group state to [`MlsGroupState::PendingCommit`],
        // storing the current [`StagedCommit`] from the commit results
        self.group_state = MlsGroupState::PendingCommit(Box::new(PendingCommitState::Member(
            create_commit_result.staged_commit,
        )));

        // Since the state of the group might be changed, arm the state flag
        self.flag_state_change();

        Ok((
            mls_message,
            create_commit_result
                .welcome_option
                .map(|w| MlsMessageOut::from_welcome(w, self.group.version())),
            create_commit_result.group_info,
        ))
    }

    pub fn remove_reqs<KeyStore: OpenMlsKeyStore>(
        &mut self,
        provider: &impl OpenMlsProvider<KeyStoreProvider = KeyStore>,
        signer: &impl Signer,
        indexes: &[u32]
    ) -> Result<
        (MlsMessageOut, Option<MlsMessageOut>, Option<GroupInfo>),
        RemoveReqsError<KeyStore::Error>,
    > {
        self.is_operational()?;

        if indexes.is_empty() {
            return Err(RemoveReqsError::EmptyInput(EmptyInputError::RemoveReqs));
        }

        // Create inline remove proposals
        let mut inline_proposals = Vec::new();
        for index in indexes.iter() {
            inline_proposals.push(Proposal::RemoveReqs(RemoveReqsProposal { index: *index }));
        }

        // Create Commit over all proposals
        // TODO #751
        let params = CreateCommitParams::builder()
            .framing_parameters(self.framing_parameters())
            .proposal_store(&self.proposal_store)
            .inline_proposals(inline_proposals)
            .build();
        let create_commit_result = self.group.create_commit(params, provider, signer)?;

        // Convert PublicMessage messages to MLSMessage and encrypt them if required by
        // the configuration
        let mls_message = self.content_to_mls_message(create_commit_result.commit, provider)?;

        // Set the current group state to [`MlsGroupState::PendingCommit`],
        // storing the current [`StagedCommit`] from the commit results
        self.group_state = MlsGroupState::PendingCommit(Box::new(PendingCommitState::Member(
            create_commit_result.staged_commit,
        )));

        // Since the state of the group might be changed, arm the state flag
        self.flag_state_change();

        Ok((
            mls_message,
            create_commit_result
                .welcome_option
                .map(|w| MlsMessageOut::from_welcome(w, self.group.version())),
            create_commit_result.group_info,
        ))
    }
}