# SNS CLI
`sns` is a command-line tool (CLI) that can be used to initialize, deploy and interact with an SNS (Service Nervous System)

## Deployment
The following instructions will guide you through deploying an SNS.

### Prerequisites

Verify the following before deploying locally:

* You have installed the [Rust toolchain](https://www.rust-lang.org/learn/get-started) (e.g. cargo)

* You have downloaded and installed `dfx`, i.e. the [DFINITY Canister SDK](https://sdk.dfinity.org).

* You have stopped any Internet Computer or other network process that would
  create a port conflict on 8000.

* You have locally cloned the [ic](https://github.com/dfinity/ic) repo.

* You have downloaded and installed the [ic-cdk-optimizer](https://smartcontracts.org/docs/rust-guide/rust-optimize.html#_install_and_run_the_optimizer).

* You have installed [nix](https://nixos.org/manual/nix/stable/installation/installing-binary.html) and can run `nix-shell`.

### Building `sns` and the SNS canisters
Within the `ic` repo, `cd` into `rs/` and enter `nix-shell`:
```shell
cd rs; nix-shell
```
`cd` into `sns/cli/`:
```shell
cd sns/cli
```
To build only `sns`, run
```shell
cargo build
```
To build the `sns` CLI and the SNS canisters, run:
```shell
make
```
The rest of this demo assumes that the `sns` binary is on your `PATH`. The location of the
`sns` depends on your environment, but it may be at a location similar to:
```shell
ic/rs/target/x86_64-apple-darwin/debug/sns
```
Add this location to your `PATH`. For example on Mac OS:
```shell
export PATH="<PATH_TO_PROJECT>/ic/rs/target/x86_64-apple-darwin/debug:$PATH"
```

### Deployment Arguments 
There are many parameters necessary to deploy an SNS, these parameters are passed to the CLI tool in a *yaml* file. 
Command `init-config-file` provides functionality to create and validate this file.
```shell
sns init-config-file new
```
Creates a new template file, by default with the name *sns_init.yaml*, that contains all the parameters necessary.
The parameters that dont need to be set by the user are set to the default value, and can be changed. The parameters
that need to be set are empty, and the deployment will not work unless a valid value is specified for them.

There is also command:
```shell
sns init-config-file validate
```
It will check that all parameters are set to valid values.

### Local Deployment
If you wish to remove state from past local deployments (to do a clean local deploy), run:
```shell
make clean
```
In a separate tab (still in `rs/sns/cli/`), start a local Internet Computer network:
```shell
dfx start
```

#### Barebones deploy
To deploy SNS locally without any customization, run:
```shell
sns init-config-file new
```
fill the mandatory parameters, and them run:
```shell
sns deploy --initial-cycles-per-canister 200000000000 --init-config-file sns_init.yaml
```
(assuming `sns` is in your `PATH`)

You should see the output of calls to `get_nervous_system_parameters` and `transfer_fee`, and see a 
"Successfully deployed!" message if the deployment was successful.

There are other SNS parameters that can be customized, to view them run:
```shell
sns deploy --help
```

### IC Deployment
To deploy to the public Internet Computer (IC) network, `cd` into `rs/` and enter `nix-shell`:
```shell
cd rs;
nix-shell
```
cd to `rs/sns/cli` and build `sns` CLI and the SNS canisters (skip this step if canisters and `sns` CLI are already built):
```shell
cd sns/cli;
make
```
Ensure there are cycles in your cycles wallet. If you don't have any cycles, follow 
[these instructions](https://smartcontracts.org/docs/quickstart/4-quickstart.html) to acquire cycles. Choose a desired
amount of cycles to initialize each SNS canister with (here we choose 200B cycles), choose a token name and symbol, 
specify any optional params and call:
```shell
sns deploy --network ic --initial-cycles-per-canister 200000000000 --init-config-file sns_init.yaml 
```
