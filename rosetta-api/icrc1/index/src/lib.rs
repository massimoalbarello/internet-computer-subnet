use std::cell::RefCell;
use std::collections::{btree_map, BTreeMap};

use candid::{CandidType, Nat};
use ic_base_types::{CanisterId, PrincipalId};
use ic_cdk::api::stable::{StableReader, StableWriter};
use ic_icrc1::endpoints::{ArchivedTransactionRange, TransactionRange};
use ic_icrc1::{
    endpoints::{GetTransactionsRequest, GetTransactionsResponse, Transaction, Transfer},
    Account, Subaccount,
};
use num_traits::cast::ToPrimitive;
use serde::{Deserialize, Serialize};
use std::ops::Bound::{Included, Unbounded};

// Maximum number of transactions that can be returned
// by [get_account_transactions]
const MAX_TRANSACTIONS_PER_RESPONSE: usize = 1000;
// Maximum number of subaccounts that can be returned
// by [list_subaccounts]
const MAX_SUBACCOUNTS_PER_RESPONSE: usize = 1000;

const LOG_PREFIX: &str = "[ic-icrc1-index] ";

type TxId = u64;

#[derive(Serialize, Deserialize, Debug)]
struct Index {
    // The id of the Ledger canister to index
    pub ledger_id: CanisterId,

    // The next txid to query from the Ledger
    pub next_txid: TxId,

    // Whether there is a [heartbeat] running right now
    pub is_heartbeat_running: bool,

    // The index of transactions per account
    pub account_index: BTreeMap<PrincipalId, BTreeMap<Subaccount, Vec<TxId>>>,

    // The number of unique (principal, subaccount) pairs in the index.
    pub accounts_num: u64,
}

impl Index {
    fn from(init_args: InitArgs) -> Self {
        Self {
            ledger_id: init_args.ledger_id,
            next_txid: 0,
            is_heartbeat_running: false,
            account_index: BTreeMap::new(),
            accounts_num: 0,
        }
    }
}

thread_local! {
    static INDEX: RefCell<Option<Index>>  = RefCell::new(None);
}

fn with_index<R>(f: impl FnOnce(&Index) -> R) -> R {
    INDEX.with(|idx| f(idx.borrow().as_ref().expect("Index state is not set!")))
}

fn with_index_mut<R>(f: impl FnOnce(&mut Index) -> R) -> R {
    INDEX.with(|idx| f(idx.borrow_mut().as_mut().expect("Index state is not set!")))
}

pub fn ledger_id() -> CanisterId {
    with_index(|idx| idx.ledger_id)
}

#[derive(CandidType, Clone, Debug, candid::Deserialize)]
pub struct InitArgs {
    // The Ledger canister id of the Ledger to index
    pub ledger_id: CanisterId,
}

pub fn init(init_args: InitArgs) {
    INDEX.with(|idx| *idx.borrow_mut() = Some(Index::from(init_args)));
}

#[derive(CandidType, Debug, candid::Deserialize, PartialEq)]
pub struct GetAccountTransactionsArgs {
    pub account: Account,
    // The txid of the last transaction seen by the client.
    // If None then the results will start from the most recent
    // txid.
    pub start: Option<Nat>,
    // Maximum number of transactions to fetch.
    pub max_results: Nat,
}

#[derive(CandidType, Debug, candid::Deserialize, PartialEq)]
pub struct TransactionWithId {
    pub id: Nat,
    pub transaction: Transaction,
}

#[derive(CandidType, Debug, candid::Deserialize, PartialEq)]
pub struct GetTransactions {
    pub transactions: Vec<TransactionWithId>,
    // The txid of the oldest transaction the account has
    pub oldest_tx_id: Option<TxId>,
}

#[derive(CandidType, Debug, candid::Deserialize, PartialEq)]
pub struct GetTransactionsErr {
    pub message: String,
}

pub type GetTransactionsResult = Result<GetTransactions, GetTransactionsErr>;

#[derive(CandidType, Debug, Deserialize, PartialEq)]
pub struct ListSubaccountsArgs {
    pub owner: PrincipalId,
    // The last subaccount seen by the client for the given principal.
    // This subaccount is included in the result.
    // If None then the results will start from the first
    // in natural order.
    pub start: Option<Subaccount>,
}

pub fn list_subaccounts(list_subaccounts_args: ListSubaccountsArgs) -> Vec<Subaccount> {
    with_index(
        |idx| match idx.account_index.get(&list_subaccounts_args.owner) {
            None => vec![],
            Some(subaccounts) => subaccounts
                .range((
                    list_subaccounts_args
                        .start
                        .map(Included)
                        .unwrap_or(Unbounded),
                    Unbounded,
                ))
                .take(MAX_SUBACCOUNTS_PER_RESPONSE)
                .map(|(k, _)| *k)
                .collect(),
        },
    )
}

pub async fn heartbeat() {
    if with_index(|idx| idx.is_heartbeat_running) {
        return;
    }
    with_index_mut(|idx| idx.is_heartbeat_running = true);

    if let Err(err) = build_index().await {
        ic_cdk::eprintln!("{}Failed to fetch blocks: {}", LOG_PREFIX, err);
    }

    with_index_mut(|idx| idx.is_heartbeat_running = false);
}

async fn get_transactions_from_ledger(
    start: u64,
    length: usize,
) -> Result<GetTransactionsResponse, String> {
    let ledger_id = ledger_id();
    let req = GetTransactionsRequest {
        start: Nat::from(start),
        length: Nat::from(length),
    };
    let (res,): (GetTransactionsResponse,) =
        ic_cdk::call(ledger_id.get().0, "get_transactions", (req,))
            .await
            .map_err(|(code, str)| format!("code: {:#?} message: {}", code, str))?;
    Ok(res)
}

async fn get_transactions_from_archive(
    archived: &ArchivedTransactionRange,
) -> Result<TransactionRange, String> {
    let req = GetTransactionsRequest {
        start: archived.start.clone(),
        length: archived.length.clone(),
    };
    let (res,): (TransactionRange,) = ic_cdk::call(
        archived.callback.canister_id.get().0,
        &archived.callback.method,
        (req,),
    )
    .await
    .map_err(|(code, str)| format!("code: {:#?} message: {}", code, str))?;
    Ok(res)
}

async fn build_index() -> Result<(), String> {
    let next_txid = with_index(|idx| idx.next_txid);
    let res = get_transactions_from_ledger(next_txid, MAX_TRANSACTIONS_PER_RESPONSE).await?;
    for archived in res.archived_transactions {
        let res = get_transactions_from_archive(&archived).await?;
        let mut idx = archived
            .start
            .0
            .to_u64()
            .expect("The Ledger returned an index that is not a valid u64");
        for transaction in res.transactions {
            index_transaction(idx, transaction)?;
            idx += 1;
        }
    }
    let mut idx = res
        .first_index
        .0
        .to_u64()
        .expect("The Ledger returned an index that is not a valid u64");
    for transaction in res.transactions {
        index_transaction(idx, transaction)?;
        idx += 1;
    }
    Ok(())
}

fn index_transaction(txid: u64, transaction: Transaction) -> Result<(), String> {
    match transaction.kind.as_str() {
        "mint" => {
            add_tx(txid, transaction.mint.unwrap().to);
            Ok(())
        }
        "burn" => {
            add_tx(txid, transaction.burn.unwrap().from);
            Ok(())
        }
        "transfer" => {
            let Transfer { from, to, .. } = transaction.transfer.unwrap();
            add_tx(txid, from);
            add_tx(txid, to);
            Ok(())
        }
        kind => Err(format!("Found transaction of unknown kind {}", kind)),
    }
}

fn add_tx(txid: u64, account: Account) {
    with_index_mut(|idx| {
        let account_index = match idx.account_index.entry(account.owner) {
            btree_map::Entry::Vacant(v) => v.insert(BTreeMap::new()),
            btree_map::Entry::Occupied(o) => o.into_mut(),
        };
        match account_index.entry(*account.effective_subaccount()) {
            btree_map::Entry::Vacant(v) => {
                idx.accounts_num += 1;
                let _ = v.insert(vec![txid]);
            }
            btree_map::Entry::Occupied(o) => o.into_mut().push(txid),
        };
        idx.next_txid = txid + 1;
    });
}

/// Returns args.max_results transactions ids of the account args.account
/// since args.start.
/// The transactions will be sorted from the most recent to the least recent.
///
/// If arg.start is not set then it represents the max txid. A query with
/// start=None will always return the most recent transaction as first transaction
///
/// Examples [1, 3, 5, 6, 9]:
/// start=None  max_results=3 => [9, 6, 5]  // last 3
/// start=9     max_results=3 => [9, 6, 5]  // last 3 before 10
/// start=5     max_results=2 => [5, 3]     // last 2 after 5
/// start=3     max_results=3 => [3, 1]     // last 3 before 3 but there are only 2 txs
/// start=0     max_results=2 => []         // start is before oldest txid
fn get_account_transactions_ids(args: GetAccountTransactionsArgs) -> Vec<TxId> {
    // The SNS Ledger txid (or block index) is a u64
    if args.start.is_some() && (&args.start).as_ref().unwrap() > &Nat::from(u64::MAX) {
        return vec![];
    }
    let max_results = (&args.max_results)
        .min(&Nat::from(MAX_TRANSACTIONS_PER_RESPONSE))
        .0
        .to_usize()
        .unwrap();
    with_index(|idx| {
        let account_index = match idx.account_index.get(&args.account.owner) {
            Some(account_index) => account_index,
            None => return vec![],
        };
        let txids = match account_index.get(args.account.effective_subaccount()) {
            Some(txids) => txids,
            None => return vec![],
        };
        let start_pos = match &args.start {
            None => txids.len() - 1,
            // binary_search doc:
            // If the value is found then Result::Ok is returned, containing the index
            // of the matching element. ... If the value is not found then Result::Err
            // is returned, containing the index where a matching element could be
            // inserted while maintaining sorted order.
            Some(start) => match txids.binary_search(&start.0.to_u64().unwrap()) {
                Ok(i) => i,
                Err(i) if i > 0 => i - 1,
                _ => return vec![],
            },
        };
        let end_pos = (start_pos as i64 - max_results as i64 + 1).max(0) as usize;
        (end_pos..=start_pos)
            .rev()
            .map(|pos| *txids.get(pos).unwrap())
            .collect()
    })
}

pub async fn get_account_transactions(args: GetAccountTransactionsArgs) -> GetTransactionsResult {
    let txids = get_account_transactions_ids(args);
    let mut txs = vec![];
    for txid in &txids {
        match get_transactions_from_ledger(*txid, 1).await {
            Ok(mut res) => {
                if let Some(tx) = res.transactions.pop() {
                    txs.push(TransactionWithId {
                        id: Nat::from(*txid),
                        transaction: tx,
                    })
                } else if let Some(archive) = res.archived_transactions.get(0) {
                    match get_transactions_from_archive(archive).await {
                        Ok(res) if !res.transactions.is_empty() => txs.push(TransactionWithId {
                            id: Nat::from(*txid),
                            transaction: res.transactions.get(0).unwrap().clone(),
                        }),
                        Ok(_) => {
                            let message = format!("Error fetching transaction {} from archive {}: archive didn't   return the transaction!", txid, archive.callback.canister_id);
                            ic_cdk::eprintln!("{}{}", LOG_PREFIX, message);
                            return Err(GetTransactionsErr { message });
                        }
                        Err(e) => {
                            let message = format!(
                                "Error fetching transaction {}from archive {}: {}",
                                txid, archive.callback.canister_id, e
                            );
                            ic_cdk::eprintln!("{}{}", LOG_PREFIX, message);
                            return Err(GetTransactionsErr { message });
                        }
                    }
                }
            }
            Err(e) => {
                let message = format!("Error fetching transaction {}: {}", txid, e);
                ic_cdk::eprintln!("{}{}", LOG_PREFIX, message);
                return Err(GetTransactionsErr { message });
            }
        }
    }
    Ok(GetTransactions {
        transactions: txs,
        oldest_tx_id: txids.get(0).cloned(),
    })
}

pub fn encode_metrics(w: &mut ic_metrics_encoder::MetricsEncoder<Vec<u8>>) -> std::io::Result<()> {
    w.encode_gauge(
        "index_stable_memory_pages",
        dfn_core::api::stable_memory_size_in_pages() as f64,
        "Size of the stable memory allocated by this canister measured in 64K Wasm pages.",
    )?;
    w.encode_gauge(
        "index_stable_memory_bytes",
        (dfn_core::api::stable_memory_size_in_pages() * 64 * 1024) as f64,
        "Size of the stable memory allocated by this canister.",
    )?;
    w.encode_gauge(
        "index_number_of_transactions",
        with_index(|idx| idx.next_txid) as f64,
        "Total number of transaction stored in the main memory.",
    )?;
    w.encode_gauge(
        "index_number_of_accounts",
        with_index(|idx| idx.accounts_num) as f64,
        "Total number of accounts indexed.",
    )?;
    Ok(())
}

pub fn pre_upgrade() {
    with_index(|idx| ciborium::ser::into_writer(idx, StableWriter::default()))
        .expect("failed to encode index state");
}

pub fn post_upgrade() {
    INDEX.with(|idx| {
        *idx.borrow_mut() = Some(
            ciborium::de::from_reader(StableReader::default())
                .expect("failed to decode index state"),
        )
    });
}

#[cfg(test)]
mod tests {
    use std::collections::{btree_map, BTreeMap};

    use candid::Nat;
    use ic_base_types::{CanisterId, PrincipalId};
    use ic_icrc1::Account;

    use proptest::{option, proptest};

    use crate::{
        add_tx, get_account_transactions_ids, with_index, GetAccountTransactionsArgs, Index, TxId,
        INDEX,
    };

    fn account(n: u64) -> Account {
        Account {
            owner: PrincipalId::new_user_test_id(n),
            subaccount: None,
        }
    }

    fn init_state(txids: Vec<(Account, Vec<TxId>)>) {
        INDEX.with(|idx| {
            let mut account_index = BTreeMap::new();
            for (account, new_txids) in txids {
                let account_index = match account_index.entry(account.owner) {
                    btree_map::Entry::Vacant(v) => v.insert(BTreeMap::new()),
                    btree_map::Entry::Occupied(o) => o.into_mut(),
                };
                let txids = match account_index.entry(*account.effective_subaccount()) {
                    btree_map::Entry::Vacant(v) => v.insert(vec![]),
                    btree_map::Entry::Occupied(o) => o.into_mut(),
                };
                txids.extend(new_txids);
            }
            *idx.borrow_mut() = Some(Index {
                ledger_id: CanisterId::from_u64(42),
                next_txid: 0,
                is_heartbeat_running: false,
                account_index,
                accounts_num: 0,
            });
        });
    }

    fn check_get_account_transactions_ids(
        start: Option<u64>,
        max_results: u64,
        expected: Vec<u64>,
    ) {
        let actual = get_account_transactions_ids(GetAccountTransactionsArgs {
            account: account(1),
            start: start.map(|s| Nat::from(s)),
            max_results: Nat::from(max_results),
        });
        assert_eq!(
            actual, expected,
            "start: {:?} max_results: {}",
            start, max_results
        );
    }

    proptest! {
        #[test]
        fn get_account_transactions_ids_no_account_fuzzy(start in option::of(u64::MIN..u64::MAX), max_results in u64::MIN..u64::MAX) {
            init_state(vec![]);
            check_get_account_transactions_ids(start, max_results, vec![]);
        }
    }

    #[test]
    fn get_account_transactions_start_none() {
        init_state(vec![(account(1), vec![1, 3, 5, 6, 9])]);

        // first element
        check_get_account_transactions_ids(None, 1, vec![9]);

        // first 2 elements
        check_get_account_transactions_ids(None, 2, vec![9, 6]);

        // all elements
        check_get_account_transactions_ids(None, 5, vec![9, 6, 5, 3, 1]);
    }

    proptest! {
        #[test]
        fn get_account_transactions_from_end_fuzzy(max_results in 6u64..) {
            init_state(vec![(account(1), vec![1, 3, 5, 6, 9])]);

            // max_results > num transactions
            check_get_account_transactions_ids(None, max_results, vec![9, 6, 5, 3, 1]);
        }
    }

    #[test]
    fn get_account_transactions_start_some() {
        init_state(vec![(account(1), vec![1, 3, 5, 6, 9])]);

        // start matches an existing txid, return that tx
        check_get_account_transactions_ids(Some(3), 1, vec![3]);

        // start matches an existing txid, return that tx with the previous one
        check_get_account_transactions_ids(Some(5), 2, vec![5, 3]);

        // start matches the last txid, return the last tx and the previous one
        check_get_account_transactions_ids(Some(9), 2, vec![9, 6]);

        // start matches the first txid, return that tx
        check_get_account_transactions_ids(Some(1), 2, vec![1]);

        // start doesn't match an existing txid and there is 1 tx that has txid < start, return that
        check_get_account_transactions_ids(Some(2), 1, vec![1]);

        // start doesn't match an existing txid and there are no txs with txid < start
        check_get_account_transactions_ids(Some(0), 1, vec![]);

        // start is bigger than any other txid, return the last tx
        check_get_account_transactions_ids(Some(10), 1, vec![9]);
    }

    proptest! {
        #[test]
        fn get_account_transactions_start_some_fuzzy(max_results in 5u64..) {
            init_state(vec![(account(1), vec![1, 3, 5, 6, 9])]);

            // all results from each existing txid
            check_get_account_transactions_ids(Some(0), max_results, vec![]);
            check_get_account_transactions_ids(Some(1), max_results, vec![1]);
            check_get_account_transactions_ids(Some(3), max_results, vec![3, 1]);
            check_get_account_transactions_ids(Some(5), max_results, vec![5, 3, 1]);
            check_get_account_transactions_ids(Some(6), max_results, vec![6, 5, 3, 1]);
            check_get_account_transactions_ids(Some(9), max_results, vec![9, 6, 5, 3, 1]);

            // all results from non-existing txid
            check_get_account_transactions_ids(Some(2), max_results, vec![1]);
            check_get_account_transactions_ids(Some(4), max_results, vec![3, 1]);
            check_get_account_transactions_ids(Some(7), max_results, vec![6, 5, 3, 1]);
            check_get_account_transactions_ids(Some(8), max_results, vec![6, 5, 3, 1]);
            check_get_account_transactions_ids(Some(10), max_results, vec![9, 6, 5, 3, 1]);
        }

        #[test]
        fn get_account_transactions_start_some_fuzzy_out_of_range(max_results in 0u64..) {
            init_state(vec![(account(1), vec![1, 3, 5, 6, 9])]);

            // start = 0 so the results must always be empty
            check_get_account_transactions_ids(Some(0), max_results, vec![]);
        }
    }

    proptest! {
        #[test]
        fn get_account_transactions_check_panics(start in option::of(0u64..), max_results in u64::MIN..u64::MAX) {
            init_state(vec![(account(1), vec![1, 3, 5, 6, 9])]);

            get_account_transactions_ids(GetAccountTransactionsArgs {
                account: account(1),
                start: start.map(|x| Nat::from(x)),
                max_results: Nat::from(max_results),
            });
        }
    }

    #[test]
    fn account_num() {
        init_state(vec![]);

        let mut next_txid = 0u64..;
        let mut add_tx_for = |principal: u64, subaccount_number: u64| -> u64 {
            let mut subaccount = [0u8; 32];
            subaccount[0..8].copy_from_slice(&subaccount_number.to_le_bytes());
            let account = Account {
                owner: PrincipalId::new_user_test_id(principal),
                subaccount: Some(subaccount),
            };
            add_tx(next_txid.next().unwrap(), account);
            with_index(|idx| idx.accounts_num)
        };

        // no accounts at the beginning
        assert_eq!(0, with_index(|idx| idx.accounts_num));

        // new tx for new principal => add one account
        assert_eq!(1, add_tx_for(0, 0));

        // new tx for existing principal => same number of accounts
        assert_eq!(1, add_tx_for(0, 0));

        // new tx for new principal => add one account
        assert_eq!(2, add_tx_for(1, 0));

        // new tx for existing principals => same number of accounts
        assert_eq!(2, add_tx_for(0, 0));
        assert_eq!(2, add_tx_for(1, 0));

        // new tx for exiting principals but new subaccount
        assert_eq!(3, add_tx_for(0, 1));
        assert_eq!(3, add_tx_for(0, 1));
        assert_eq!(4, add_tx_for(0, 2));
        assert_eq!(4, add_tx_for(0, 2));
        assert_eq!(5, add_tx_for(1, 1));
        assert_eq!(5, add_tx_for(1, 1));

        // new tx for new principal and different subaccounts
        assert_eq!(6, add_tx_for(2, 1));
        assert_eq!(7, add_tx_for(2, 3));
        assert_eq!(8, add_tx_for(2, 10));
    }
}
