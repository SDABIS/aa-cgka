use serde_json::Value;
use openmls_traits::signatures::Signer;

use super::*;
use crate::{messages::group_info::GroupInfo};
use crate::group::{AddReqsError, EmptyInputError, RemoveReqsError, UpdateReqsError};

impl MlsGroup {
    pub fn add_new_reqs<Provider: OpenMlsProvider>(
        &mut self,
        provider: &Provider,
        signer: &impl Signer,
        new_reqs: &[Value],
    ) -> Result<
        (MlsMessageOut, Option<MlsMessageOut>, Option<GroupInfo>),
        AddReqsError<Provider::StorageError>,
    > {
        self.is_operational()?;

        if new_reqs.is_empty() {
            return Err(AddReqsError::EmptyInput(EmptyInputError::AddReqs));
        }

        let bundle = self
            .commit_builder()
            .propose_add_reqs(new_reqs.iter().cloned())
            .load_psks(provider.storage())?
            .build(provider.rand(), provider.crypto(), signer, |_| true)?
            .stage_commit(provider)?;

        let welcome = bundle.to_welcome_msg();
        let (commit, _, group_info) = bundle.into_contents();

        /*provider
            .storage()
            .write_group_state(self.group_id(), &self.group_state)
            .map_err(RemoveMembersError::StorageError)?;*/

        self.reset_aad();
        Ok((commit, welcome, group_info))
    }

    pub fn update_reqs<Provider: OpenMlsProvider>(
        &mut self,
        provider: &Provider,
        signer: &impl Signer,
        new_req: &Value,
        index: u32
    ) -> Result<
        (MlsMessageOut, Option<MlsMessageOut>, Option<GroupInfo>),
        UpdateReqsError<Provider::StorageError>,
    > {
        self.is_operational()?;

        let bundle = self
            .commit_builder()
            .propose_update_reqs(index, new_req.clone())
            .load_psks(provider.storage())?
            .build(provider.rand(), provider.crypto(), signer, |_| true)?
            .stage_commit(provider)?;

        let welcome = bundle.to_welcome_msg();
        let (commit, _, group_info) = bundle.into_contents();

        /*provider
            .storage()
            .write_group_state(self.group_id(), &self.group_state)
            .map_err(RemoveMembersError::StorageError)?;*/

        self.reset_aad();
        Ok((commit, welcome, group_info))
    }

    pub fn remove_reqs<Provider: OpenMlsProvider>(
        &mut self,
        provider: &Provider,
        signer: &impl Signer,
        indexes: &[u32]
    ) -> Result<
        (MlsMessageOut, Option<MlsMessageOut>, Option<GroupInfo>),
        RemoveReqsError<Provider::StorageError>,
    > {
        self.is_operational()?;

        if indexes.is_empty() {
            return Err(RemoveReqsError::EmptyInput(EmptyInputError::RemoveReqs));
        }

        let bundle = self
            .commit_builder()
            .propose_removal_reqs(indexes.iter().cloned())
            .load_psks(provider.storage())?
            .build(provider.rand(), provider.crypto(), signer, |_| true)?
            .stage_commit(provider)?;

        let welcome = bundle.to_welcome_msg();
        let (commit, _, group_info) = bundle.into_contents();

        /*provider
            .storage()
            .write_group_state(self.group_id(), &self.group_state)
            .map_err(RemoveMembersError::StorageError)?;*/

        self.reset_aad();
        Ok((commit, welcome, group_info))
    }
}