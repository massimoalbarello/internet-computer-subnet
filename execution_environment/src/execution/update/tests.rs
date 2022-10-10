use ic_base_types::NumSeconds;
use ic_embedders::DIRTY_PAGE_TO_INSTRUCTION_RATE;
use ic_error_types::ErrorCode;
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::canister_state::NextExecution;
use ic_state_machine_tests::Cycles;
use ic_types::NumInstructions;
use ic_universal_canister::{call_args, wasm};

use crate::execution::test_utilities::{check_ingress_status, ExecutionTest, ExecutionTestBuilder};

const GB: u64 = 1024 * 1024 * 1024;

fn wat_writing_to_each_stable_memory_page(memory_amount: u64) -> String {
    format!(
        r#"
        (module
            (import "ic0" "stable64_write"
                (func $stable_write (param $offset i64) (param $src i64) (param $size i64))
            )
            (import "ic0" "stable64_grow" (func $stable_grow (param i64) (result i64)))
            (import "ic0" "msg_reply" (func $msg_reply))
            (func (export "canister_update go") (local i64)
                (local.set 0 (i64.const 0))
                (drop (call $stable_grow (i64.const 131072))) (; maximum allowed ;)
                (loop $loop
                    (call $stable_write (local.get 0) (i64.const 0) (i64.const 1))
                    (local.set 0 (i64.add (local.get 0) (i64.const 4096))) (;increment by OS page size;)
                    (br_if $loop (i64.lt_s (local.get 0) (i64.const {}))) (;loop if value is within the memory amount;)
                )
                (call $msg_reply)
            )
            (memory (export "memory") 1)
        )"#,
        memory_amount
    )
}

#[test]
fn can_write_to_each_page_in_stable_memory() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = wat_writing_to_each_stable_memory_page(7 * GB);
    let canister_id = test.canister_from_wat(wat).unwrap();
    let _result = test.ingress(canister_id, "go", vec![]).unwrap();
}

#[test]
fn dts_update_concurrent_cycles_change_succeeds() {
    // Test steps:
    // 1. Canister A starts running the update method.
    // 2. While canister A is paused, we emulate a postponed charge
    //    of 1000 cycles (i.e. add 1000 to `cycles_debit`).
    // 3. The update method resumes and calls canister B with 1000 cycles.
    // 4. The update method succeeds because there are enough cycles
    //    in the canister balance to cover both the call and cycles debit.
    let instruction_limit = 1_000_000;
    let mut test = ExecutionTestBuilder::new()
        .with_instruction_limit(instruction_limit)
        .with_slice_instruction_limit(10_000)
        .with_deterministic_time_slicing()
        .with_manual_execution()
        .build();

    let a_id = test.universal_canister().unwrap();
    let b_id = test.universal_canister().unwrap();

    let transferred_cycles = Cycles::new(1000);

    let b = wasm()
        .accept_cycles128(transferred_cycles.into_parts())
        .message_payload()
        .append_and_reply()
        .build();

    let a = wasm()
        .stable64_grow(1)
        .stable64_write(0, 0, 10_000)
        .call_with_cycles(
            b_id.get(),
            "update",
            call_args().other_side(b.clone()),
            transferred_cycles.into_parts(),
        )
        .build();

    test.canister_update_allocations_settings(a_id, Some(1), None)
        .unwrap();
    test.update_freezing_threshold(a_id, NumSeconds::from(1))
        .unwrap();

    test.ingress_raw(a_id, "update", a);

    let freezing_threshold = test.freezing_threshold(a_id);

    // The memory usage of the canister increases during the message execution.
    // `ic0.call_perform()` used the current freezing threshold. This value is
    // an upper bound on the additional freezing threshold.
    let additional_freezing_threshold = Cycles::new(500);

    let max_execution_cost = test
        .cycles_account_manager()
        .execution_cost(NumInstructions::from(instruction_limit), test.subnet_size());

    let call_charge = test.call_fee("update", &b)
        + max_execution_cost
        + test.max_response_fee()
        + transferred_cycles;

    let cycles_debit = Cycles::new(1000);

    // Reset the cycles balance to simplify cycles bookkeeping,
    let initial_cycles = freezing_threshold
        + additional_freezing_threshold
        + max_execution_cost
        + call_charge
        + cycles_debit;
    let initial_execution_cost = test.canister_execution_cost(a_id);
    *test.canister_state_mut(a_id).system_state.balance_mut() = initial_cycles;

    test.execute_slice(a_id);
    assert_eq!(
        test.canister_state(a_id).next_execution(),
        NextExecution::ContinueLong,
    );

    assert_eq!(
        test.canister_state(a_id).system_state.balance(),
        initial_cycles - max_execution_cost,
    );

    test.canister_state_mut(a_id)
        .system_state
        .add_postponed_charge_to_cycles_debit(cycles_debit);

    test.execute_message(a_id);

    assert_eq!(
        test.canister_state(a_id).next_execution(),
        NextExecution::None,
    );

    assert_eq!(
        test.canister_state(a_id).system_state.balance(),
        initial_cycles
            - call_charge
            - (test.canister_execution_cost(a_id) - initial_execution_cost)
            - cycles_debit,
    );
}

#[test]
fn dts_update_concurrent_cycles_change_fails() {
    // Test steps:
    // 1. Canister A starts running the update method.
    // 2. While canister A is paused, we emulate a postponed charge
    //    of 1000 cycles (i.e. add 1000 to `cycles_debit`).
    // 3. The update method resumes and calls canister B with 1000 cycles.
    // 4. The update method fails because there are not enough cycles
    //    in the canister balance to cover both the call and cycles debit.
    let instruction_limit = 1_000_000;
    let mut test = ExecutionTestBuilder::new()
        .with_instruction_limit(instruction_limit)
        .with_slice_instruction_limit(10_000)
        .with_deterministic_time_slicing()
        .with_manual_execution()
        .build();

    let a_id = test.universal_canister().unwrap();
    let b_id = test.universal_canister().unwrap();

    let transferred_cycles = Cycles::new(1000);

    let b = wasm()
        .accept_cycles128(transferred_cycles.into_parts())
        .message_payload()
        .append_and_reply()
        .build();

    let a = wasm()
        .stable64_grow(1)
        .stable64_write(0, 0, 10_000)
        .call_with_cycles(
            b_id.get(),
            "update",
            call_args().other_side(b.clone()),
            transferred_cycles.into_parts(),
        )
        .build();

    test.canister_update_allocations_settings(a_id, Some(1), None)
        .unwrap();
    test.update_freezing_threshold(a_id, NumSeconds::from(1))
        .unwrap();

    let (ingress_id, _) = test.ingress_raw(a_id, "update", a);

    let freezing_threshold = test.freezing_threshold(a_id);

    // The memory usage of the canister increases during the message execution.
    // `ic0.call_perform()` used the current freezing threshold. This value is
    // an upper bound on the additional freezing threshold.
    let additional_freezing_threshold = Cycles::new(500);

    let max_execution_cost = test
        .cycles_account_manager()
        .execution_cost(NumInstructions::from(instruction_limit), test.subnet_size());

    let call_charge = test.call_fee("update", &b)
        + max_execution_cost
        + test.max_response_fee()
        + transferred_cycles;

    // Reset the cycles balance to simplify cycles bookkeeping,
    let initial_cycles =
        freezing_threshold + additional_freezing_threshold + max_execution_cost + call_charge;
    let initial_execution_cost = test.canister_execution_cost(a_id);
    *test.canister_state_mut(a_id).system_state.balance_mut() = initial_cycles;

    test.execute_slice(a_id);
    assert_eq!(
        test.canister_state(a_id).next_execution(),
        NextExecution::ContinueLong,
    );

    assert_eq!(
        test.canister_state(a_id).system_state.balance(),
        initial_cycles - max_execution_cost,
    );

    let cycles_debit = test.canister_state(a_id).system_state.balance();
    test.canister_state_mut(a_id)
        .system_state
        .add_postponed_charge_to_cycles_debit(cycles_debit);

    test.execute_message(a_id);

    assert_eq!(
        test.canister_state(a_id).next_execution(),
        NextExecution::None,
    );

    let err = check_ingress_status(test.ingress_status(&ingress_id)).unwrap_err();
    assert_eq!(err.code(), ErrorCode::CanisterOutOfCycles);

    assert_eq!(
        err.description(),
        format!(
            "Canister {} is out of cycles: \
             requested {} cycles but the available balance \
             is {} cycles and the freezing threshold {} cycles",
            a_id,
            call_charge,
            initial_cycles - max_execution_cost - cycles_debit,
            freezing_threshold
        )
    );

    assert_eq!(
        test.canister_state(a_id).system_state.balance(),
        initial_cycles
            - (test.canister_execution_cost(a_id) - initial_execution_cost)
            - cycles_debit,
    );
}

#[test]
fn dirty_pages_are_free_on_system_subnet() {
    fn instructions_to_write_stable_byte(mut test: ExecutionTest) -> NumInstructions {
        let initial_cycles = Cycles::new(1_000_000_000_000);
        let a_id = test.universal_canister_with_cycles(initial_cycles).unwrap();
        let a = wasm()
            .stable_grow(1)
            .stable64_write(0, 0, 1)
            .message_payload()
            .append_and_reply()
            .build();
        let result = test.ingress(a_id, "update", a);
        assert!(result.is_ok());
        test.canister_executed_instructions(a_id)
    }

    let system_test = ExecutionTestBuilder::new()
        .with_subnet_type(SubnetType::System)
        .build();
    let system_instructions = instructions_to_write_stable_byte(system_test);
    let app_test = ExecutionTestBuilder::new()
        .with_subnet_type(SubnetType::Application)
        .build();
    let app_instructions = instructions_to_write_stable_byte(app_test);

    // Can't check for equality because there are other charges that are omitted
    // on system subnets.
    assert!(
        app_instructions
            > system_instructions + NumInstructions::from(DIRTY_PAGE_TO_INSTRUCTION_RATE)
    );
}
