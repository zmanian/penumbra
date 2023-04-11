use anyhow::Result;
use std::sync::Arc;

// TODO: we should not have dependencies on penumbra_chain in narsil
// and instead implement narsil-specific state accessors or extract
// the common accessors elsewhere to avoid mingling penumbra-specific logic.
use penumbra_chain::{genesis, AppHash, StateReadExt};
use penumbra_proto::{core::transaction::v1alpha1::Transaction, Message};
use penumbra_storage::{ArcStateDeltaExt, Snapshot, StateDelta, Storage};
use tendermint::{abci, validator::Update};

/// The Narsil application.
pub struct App {
    state: Arc<StateDelta<Snapshot>>,
}

impl App {
    pub async fn new(snapshot: Snapshot) -> Result<Self> {
        tracing::debug!("initializing App instance");

        // We perform the `Arc` wrapping of `State` here to ensure
        // there should be no unexpected copies elsewhere.
        let state = Arc::new(StateDelta::new(snapshot));

        // If the state says that the chain is halted, we should not proceed. This is a safety check
        // to ensure that automatic restarts by software like systemd do not cause the chain to come
        // back up again after a halt.
        if state.is_chain_halted(TOTAL_HALT_COUNT).await? {
            anyhow::bail!("chain is halted, refusing to restart");
        }

        Ok(Self { state })
    }

    pub async fn init_chain(&mut self, _app_state: &genesis::AppState) {
        let state_tx = self
            .state
            .try_begin_transaction()
            .expect("state Arc should not be referenced elsewhere");

        state_tx.apply();
    }

    pub async fn begin_block(
        &mut self,
        _begin_block: &abci::request::BeginBlock,
    ) -> Vec<abci::Event> {
        let state_tx = self
            .state
            .try_begin_transaction()
            .expect("state Arc should not be referenced elsewhere");

        let events = state_tx.apply().1;

        events
    }

    /// Wrapper function for [`Self::deliver_tx`]  that decodes from bytes.
    pub async fn deliver_tx_bytes(&mut self, tx_bytes: &[u8]) -> Result<Vec<abci::Event>> {
        let tx = Arc::new(Transaction::decode(tx_bytes)?);
        self.deliver_tx(tx).await
    }

    pub async fn deliver_tx(&mut self, _tx: Arc<Transaction>) -> Result<Vec<abci::Event>> {
        Ok(vec![])
    }

    pub async fn end_block(&mut self, _end_block: &abci::request::EndBlock) -> Vec<abci::Event> {
        let state_tx = self
            .state
            .try_begin_transaction()
            .expect("state Arc should not be referenced elsewhere");

        state_tx.apply().1
    }

    /// Commits the application state to persistent storage,
    /// returning the new root hash and storage version.
    ///
    /// This method also resets `self` as if it were constructed
    /// as an empty state over top of the newly written storage.
    pub async fn commit(&mut self, storage: Storage) -> AppHash {
        // We need to extract the State we've built up to commit it.  Fill in a dummy state.
        let dummy_state = StateDelta::new(storage.latest_snapshot());
        let state = Arc::try_unwrap(std::mem::replace(&mut self.state, Arc::new(dummy_state)))
            .expect("we have exclusive ownership of the State at commit()");

        // Check if someone has signaled that we should halt.
        let should_halt = state
            .is_chain_halted(TOTAL_HALT_COUNT)
            .await
            .expect("must be able to read halt flag");

        // Commit the pending writes, clearing the state.
        let jmt_root = storage
            .commit(state)
            .await
            .expect("must be able to successfully commit to storage");

        // If we should halt, we should end the process here.
        if should_halt {
            tracing::info!("committed block when a chain halt was signaled; exiting now");
            std::process::exit(0);
        }

        let app_hash: AppHash = jmt_root.into();

        tracing::debug!(?app_hash, "finished committing state");

        // Get the latest version of the state, now that we've committed it.
        self.state = Arc::new(StateDelta::new(storage.latest_snapshot()));

        app_hash
    }

    // TODO: should this just be returned by `commit`? both are called during every `EndBlock`
    pub fn tendermint_validator_updates(&self) -> Vec<Update> {
        todo!()
        // self.state
        //     .tendermint_validator_updates()
        //     // If the tendermint validator updates are not set, we return an empty
        //     // update set, signaling no change to Tendermint.
        //     .unwrap_or_default()
    }
}

/// The total number of times the chain has been halted.
///
/// Increment this manually after fixing the root cause for a chain halt: updated nodes will then be
/// able to proceed past the block height of the halt.
const TOTAL_HALT_COUNT: u64 = 0;
