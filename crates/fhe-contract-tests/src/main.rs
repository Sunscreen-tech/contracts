mod bindings;

use std::future::Future;
use std::iter::zip;
use std::pin::Pin;
use std::sync::Arc;

use bindings::FHE;
use clap::{Parser, Subcommand};
use colored::Colorize;
use crypto_bigint::{Limb, Uint};
use ethers::{
    core::types::{Address, Bytes, U256},
    prelude::SignerMiddleware,
    providers::{Http, Provider},
    signers::{LocalWallet, Signer},
    utils::Anvil,
};
use eyre::{eyre, Result};
use fhe_precompiles::pack::{pack_one_argument, unpack_one_argument};
use fhe_precompiles::testnet::one::FHE;
use futures::future::join_all;
use sunscreen_web3::{
    testing::{Node, ALICE, ANVIL_MNEMONIC},
    testnet::parasol::{generate_keys, PARASOL, RUNTIME},
    Fractional, Signed, Unsigned256, Unsigned64,
};

type FheContract = FHE<Provider<Http>>;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

const DEFAULT_PORT: u16 = 8545;
const DEFAULT_ENDPOINT: &str = "http://localhost:8545";

/// Default gas price for operations.
const GAS_PRICE: u32 = 300_000_000;
const GAS_PRICE_DEPLOY: u32 = GAS_PRICE;

/*****************************************************************************
 * Utility functions
 ****************************************************************************/

/// Run a bunch of tests in concurrently, and collect the results into either
/// unit results or error messages.
///
/// * `$named_results` - the name of the variable to store the results in
/// * `$fhe` - the FHE contract to run the tests on
/// * `$name` - the name of the test functions to run
///
/// Example:
///
/// ```ignore
/// test_names_and_results!(named_results, fhe, test1, test2);
/// for (name, result) in named_results {
///    if let Err(e) = result {
///       println!("{name}: error: {:?}", e);
///    } else {
///      println!("{name}: ok");
///    }
/// }
/// ```
macro_rules! test_names_and_results {
    ($named_results:ident, $fhe:ident, $($name:expr),*) => {
        let names = [$(stringify!($name)),*];
        let results = join_all([
            $( Box::pin($name($fhe.clone())) as Pin<Box<dyn Future<Output = Result<()>>>> ),*
        ]).await;
        let $named_results = zip(names, results);
    };
}

/// Converts an `Unsigned256` to a `U256`.
fn convert_unsigned256_to_u256(x: Unsigned256) -> U256 {
    let limbs: [Limb; 4] = Into::<Uint<4>>::into(x).to_limbs();

    let mut result = [0u8; 32];
    let mut offset = 0;
    for i in 0..4 {
        let us: u64 = limbs[i].into();
        let bytes = us.to_le_bytes();
        result[offset..offset + bytes.len()].copy_from_slice(&bytes);
        offset += bytes.len();
    }

    U256::from_little_endian(&result)
}

/// Wait until the user presses Ctrl+C or sends SIGINT/SIGTERM.
async fn wait_until_interrupt() -> Result<()> {
    use tokio::signal::unix::{signal, SignalKind};
    let mut sigint = signal(SignalKind::interrupt())?;
    let mut sigterm = signal(SignalKind::terminate())?;
    tokio::select! {
        _ = sigint.recv() => {},
        _ = sigterm.recv() => {},
    }
    Ok(())
}

/*****************************************************************************
 * Commands
 ****************************************************************************/

#[derive(Subcommand)]
enum Commands {
    /// Spin up an anvil node.
    Node {},

    /// Deploy Spether to existing anvil node
    Deploy {
        /// The endpoint of the node to connect to.
        #[arg(short = 'e', long, default_value = DEFAULT_ENDPOINT)]
        endpoint: String,
    },

    /// Register a new account and return Spether pub key
    Test {
        /// The endpoint of the node to connect to.
        #[arg(short = 'e', long, default_value = DEFAULT_ENDPOINT)]
        endpoint: String,

        /// The address to test with.
        #[arg(short = 'a', long)]
        address: Option<Address>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Either start up anvil
    if let Commands::Node {} = cli.command {
        return node().await;
    }

    match cli.command {
        Commands::Deploy { endpoint } => {
            deploy(&endpoint).await?;
            Ok(())
        }
        Commands::Test { endpoint, address } => {
            let address = {
                if address.is_none() {
                    println!("Deploying the FHE contract");
                    deploy(&endpoint).await?
                } else {
                    address.unwrap()
                }
            };

            let address_str = format!("{:#?}", address);
            println!(
                "Starting tests at {}, address {}",
                endpoint.magenta(),
                address_str.cyan()
            );
            test(&endpoint, address).await?;
            Ok(())
        }
        Commands::Node { .. } => unreachable!(),
    }
}

/*****************************************************************************
 * Subcommand implementations
 ****************************************************************************/

/// Start a local Parasol anvil node that can be killed with CTRL-C. Uses a
/// deterministic setup so the account addresses/etc are the same.
async fn node() -> Result<()> {
    println!("Starting anvil at {}", DEFAULT_ENDPOINT.magenta());

    let anvil = std::env::var("ANVIL_PATH")
        .map(Anvil::at)
        .unwrap_or_else(|_| Anvil::new())
        .port(DEFAULT_PORT)
        .chain_id(PARASOL.chain_id)
        .mnemonic(ANVIL_MNEMONIC)
        .args(["--gas-limit", "3000000000000000000"]);

    let node = Node::spawn_from(anvil);
    assert_eq!(node.anvil.endpoint(), DEFAULT_ENDPOINT);

    println!("Deploying FHE contract");
    deploy(DEFAULT_ENDPOINT).await?;

    println!("{}", "Node is up! Ctrl-c to shut it down".green());
    wait_until_interrupt().await?;
    Ok(())
}

/// Deploys the contract to the specified endpoint.
///
/// # Arguments
///
/// * `endpoint` - Endpoint to deploy the contract to.
///
/// # Returns
///
/// Returns a `Result` containing the `Address` of the deployed contract if
/// successful, or an error if the deployment fails.
async fn deploy(endpoint: &str) -> Result<Address> {
    let wallet: LocalWallet = ALICE.clone();
    let provider = Arc::new(Provider::<Http>::try_from(endpoint)?);
    let client = Arc::new(SignerMiddleware::new(
        provider,
        wallet.with_chain_id(PARASOL.chain_id),
    ));

    let contract_addr = FHE::deploy(Arc::new(client), ())?
        .gas(GAS_PRICE_DEPLOY)
        .send()
        .await?
        .address();

    let address_str = format!("{:#?}", contract_addr);
    println!("FHE contract deployed at address {}", address_str.cyan());

    Ok(contract_addr)
}

/// Asynchronously tests the given endpoint with the provided address.
///
/// # Arguments
///
/// * `endpoint` - A string slice that holds the endpoint to be tested.
/// * `address` - An `Address` struct that holds the address to be used for testing.
///               If `None`, the contract will be deployed to the endpoint.
///
/// # Returns
///
/// Returns a `Result` indicating success or failure.
async fn test(endpoint: &str, address: Address) -> Result<()> {
    let provider = Arc::new(Provider::<Http>::try_from(endpoint)?);
    let fhe = bindings::FHE::new(address, provider.clone());

    test_names_and_results!(
        named_results,
        fhe,
        test_network_public_key,
        test_add_uint_256_enc_enc // test_add_uint_256_enc_plain,
                                  // test_add_uint_256_plain_enc,
                                  // test_subtract_uint_256_enc_enc,
                                  // test_subtract_uint_256_enc_plain,
                                  // test_subtract_uint_256_plain_enc,
                                  // test_multiply_uint_256_enc_enc,
                                  // test_multiply_uint_256_enc_plain,
                                  // test_multiply_uint_256_plain_enc,
                                  // test_encrypt_decrypt_uint_256,
                                  // test_reencrypt_uint_256,
                                  // test_refresh_uint_256,
                                  // test_add_uint_64_enc_enc,
                                  // test_add_uint_64_enc_plain,
                                  // test_add_uint_64_plain_enc,
                                  // test_subtract_uint_64_enc_enc,
                                  // test_subtract_uint_64_enc_plain,
                                  // test_subtract_uint_64_plain_enc,
                                  // test_multiply_uint_64_enc_enc,
                                  // test_multiply_uint_64_enc_plain,
                                  // test_multiply_uint_64_plain_enc,
                                  // test_encrypt_decrypt_uint_64,
                                  // test_reencrypt_uint_64,
                                  // test_refresh_uint_64,
                                  // test_add_int_64_enc_enc,
                                  // test_add_int_64_enc_plain,
                                  // test_add_int_64_plain_enc,
                                  // test_subtract_int_64_enc_enc,
                                  // test_subtract_int_64_enc_plain,
                                  // test_subtract_int_64_plain_enc,
                                  // test_multiply_int_64_enc_enc,
                                  // test_multiply_int_64_enc_plain,
                                  // test_multiply_int_64_plain_enc,
                                  // test_encrypt_decrypt_int_64,
                                  // test_reencrypt_int_64,
                                  // test_refresh_int_64,
                                  // test_add_frac_64_enc_enc,
                                  // test_add_frac_64_enc_plain,
                                  // test_add_frac_64_plain_enc,
                                  // test_subtract_frac_64_enc_enc,
                                  // test_subtract_frac_64_enc_plain,
                                  // test_subtract_frac_64_plain_enc,
                                  // test_multiply_frac_64_enc_enc,
                                  // test_multiply_frac_64_enc_plain,
                                  // test_multiply_frac_64_plain_enc,
                                  // test_encrypt_decrypt_frac_64,
                                  // test_reencrypt_frac_64,
                                  // test_refresh_frac_64
    );

    let mut success = true;
    for (name, result) in named_results {
        if let Err(e) = result {
            println!("{name}: {} {}", "error:".red(), e.to_string().red());
            success = false;
        } else {
            println!("{name}: {}", "ok".green());
        }
    }

    if !success {
        return Err(eyre!("Some tests failed"));
    }

    Ok(())
}

/*****************************************************************************
 * Test functions
 ****************************************************************************/

async fn test_network_public_key(fhe: FheContract) -> Result<()> {
    let pub_key = fhe.network_public_key().gas(GAS_PRICE).call().await?;

    let len_pubk = pub_key.len();
    let len_fhe = FHE.public_key_bytes(&[]).unwrap().len();

    println!("public key length: {}", len_pubk);
    println!("fhe public key length: {}", len_fhe);

    println!("pub_key: {:?}", &pub_key[0..16]);
    println!(
        "fhe pub_key: {:?}",
        &FHE.public_key_bytes(&[]).unwrap()[0..16]
    );

    println!("pub_key: {:?}", &pub_key[(len_pubk - 12)..(len_pubk)]);
    println!(
        "fhe pub_key: {:?}",
        &FHE.public_key_bytes(&[]).unwrap()[(len_fhe - 12)..(len_fhe)]
    );

    let mut print = true;
    let mut total_mismatch = 0;
    for (k, (a, b)) in pub_key
        .iter()
        .zip(FHE.public_key_bytes(&[]).unwrap().iter())
        .enumerate()
    {
        if a != b {
            if print {
                println!("{}: {:?} {:?}", k, a, b);
                println!("pub_key: {:?}", &pub_key[(k - 12)..(k + 12)]);
                println!(
                    "fhe pub_key: {:?}",
                    &FHE.public_key_bytes(&[]).unwrap()[(k - 12)..(k + 12)]
                );
                print = false;
            }
            total_mismatch += 1;
        }
    }

    println!("total mismatch: {}", total_mismatch);

    if FHE.public_key_bytes(&[]).unwrap() != pub_key {
        return Err(eyre!("Public key mismatch"));
    }

    Ok(())
}

/** u256 tests **************************************************************/

async fn test_add_uint_256_enc_enc(fhe: FheContract) -> Result<()> {
    let a = U256::from(1234);
    let b = U256::from(62);
    let c = a + b;

    let a_enc = fhe.encrypt_uint_256(a).gas(GAS_PRICE).call().await?;
    let b_enc = fhe.encrypt_uint_256(b).gas(GAS_PRICE).call().await?;

    // let c_enc = fhe
    //     .add_uint_256_enc_enc(
    //         fhe.network_public_key().gas(GAS_PRICE).call().await?,
    //         a_enc,
    //         b_enc,
    //     )
    //     .gas(GAS_PRICE)
    //     .call()
    //     .await?;
    // let c_dec = fhe.decrypt_uint_256(c_enc).gas(GAS_PRICE).call().await?;

    // if c != c_dec {
    //     return Err(eyre!("Expected {}, got {}", c, c_dec));
    // }

    Ok(())
}

async fn test_add_uint_256_enc_plain(fhe: FheContract) -> Result<()> {
    let a = U256::from(1234);
    let b = U256::from(62);
    let c = a + b;

    let a_enc = fhe.encrypt_uint_256(a).gas(GAS_PRICE).call().await?;

    let c_enc = fhe
        .add_uint_256_enc_plain(
            fhe.network_public_key().gas(GAS_PRICE).call().await?,
            a_enc,
            b,
        )
        .gas(GAS_PRICE)
        .call()
        .await?;
    let c_dec = fhe.decrypt_uint_256(c_enc).gas(GAS_PRICE).call().await?;

    if c != c_dec {
        return Err(eyre!("Expected {}, got {}", c, c_dec));
    }

    Ok(())
}

async fn test_add_uint_256_plain_enc(fhe: FheContract) -> Result<()> {
    let a = U256::from(1234);
    let b = U256::from(62);
    let c = a + b;

    let b_enc = fhe.encrypt_uint_256(b).gas(GAS_PRICE).call().await?;

    let c_enc = fhe
        .add_uint_256_plain_enc(
            fhe.network_public_key().gas(GAS_PRICE).call().await?,
            a,
            b_enc,
        )
        .gas(GAS_PRICE)
        .call()
        .await?;
    let c_dec = fhe.decrypt_uint_256(c_enc).gas(GAS_PRICE).call().await?;

    if c != c_dec {
        return Err(eyre!("Expected {}, got {}", c, c_dec));
    }

    Ok(())
}

async fn test_subtract_uint_256_enc_enc(fhe: FheContract) -> Result<()> {
    let a = U256::from(1234);
    let b = U256::from(62);
    let c = a - b;

    let a_enc = fhe.encrypt_uint_256(a).gas(GAS_PRICE).call().await?;
    let b_enc = fhe.encrypt_uint_256(b).gas(GAS_PRICE).call().await?;

    let c_enc = fhe
        .subtract_uint_256_enc_enc(
            fhe.network_public_key().gas(GAS_PRICE).call().await?,
            a_enc,
            b_enc,
        )
        .gas(GAS_PRICE)
        .call()
        .await?;
    let c_dec = fhe.decrypt_uint_256(c_enc).gas(GAS_PRICE).call().await?;

    if c != c_dec {
        return Err(eyre!("Expected {}, got {}", c, c_dec));
    }

    Ok(())
}

async fn test_subtract_uint_256_enc_plain(fhe: FheContract) -> Result<()> {
    let a = U256::from(1234);
    let b = U256::from(62);
    let c = a - b;

    let a_enc = fhe.encrypt_uint_256(a).gas(GAS_PRICE).call().await?;

    let c_enc = fhe
        .subtract_uint_256_enc_plain(
            fhe.network_public_key().gas(GAS_PRICE).call().await?,
            a_enc,
            b,
        )
        .gas(GAS_PRICE)
        .call()
        .await?;
    let c_dec = fhe.decrypt_uint_256(c_enc).gas(GAS_PRICE).call().await?;

    if c != c_dec {
        return Err(eyre!("Expected {}, got {}", c, c_dec));
    }

    Ok(())
}

async fn test_subtract_uint_256_plain_enc(fhe: FheContract) -> Result<()> {
    let a = U256::from(1234);
    let b = U256::from(62);
    let c = a - b;

    let b_enc = fhe.encrypt_uint_256(b).gas(GAS_PRICE).call().await?;

    let c_enc = fhe
        .subtract_uint_256_plain_enc(
            fhe.network_public_key().gas(GAS_PRICE).call().await?,
            a,
            b_enc,
        )
        .gas(GAS_PRICE)
        .call()
        .await?;
    let c_dec = fhe.decrypt_uint_256(c_enc).gas(GAS_PRICE).call().await?;

    if c != c_dec {
        return Err(eyre!("Expected {}, got {}", c, c_dec));
    }

    Ok(())
}

async fn test_multiply_uint_256_enc_enc(fhe: FheContract) -> Result<()> {
    let a = U256::from(1234);
    let b = U256::from(62);
    let c = a * b;

    let a_enc = fhe.encrypt_uint_256(a).gas(GAS_PRICE).call().await?;
    let b_enc = fhe.encrypt_uint_256(b).gas(GAS_PRICE).call().await?;

    let c_enc = fhe
        .multiply_uint_256_enc_enc(
            fhe.network_public_key().gas(GAS_PRICE).call().await?,
            a_enc,
            b_enc,
        )
        .gas(GAS_PRICE)
        .call()
        .await?;
    let c_dec = fhe.decrypt_uint_256(c_enc).gas(GAS_PRICE).call().await?;

    if c != c_dec {
        return Err(eyre!("Expected {}, got {}", c, c_dec));
    }

    Ok(())
}

async fn test_multiply_uint_256_enc_plain(fhe: FheContract) -> Result<()> {
    let a = U256::from(1234);
    let b = U256::from(62);
    let c = a * b;

    let a_enc = fhe.encrypt_uint_256(a).gas(GAS_PRICE).call().await?;

    let c_enc = fhe
        .multiply_uint_256_enc_plain(
            fhe.network_public_key().gas(GAS_PRICE).call().await?,
            a_enc,
            b,
        )
        .gas(GAS_PRICE)
        .call()
        .await?;
    let c_dec = fhe.decrypt_uint_256(c_enc).gas(GAS_PRICE).call().await?;

    if c != c_dec {
        return Err(eyre!("Expected {}, got {}", c, c_dec));
    }

    Ok(())
}

async fn test_multiply_uint_256_plain_enc(fhe: FheContract) -> Result<()> {
    let a = U256::from(1234);
    let b = U256::from(62);
    let c = a * b;

    let b_enc = fhe.encrypt_uint_256(b).gas(GAS_PRICE).call().await?;

    let c_enc = fhe
        .multiply_uint_256_plain_enc(
            fhe.network_public_key().gas(GAS_PRICE).call().await?,
            a,
            b_enc,
        )
        .gas(GAS_PRICE)
        .call()
        .await?;
    let c_dec = fhe.decrypt_uint_256(c_enc).gas(GAS_PRICE).call().await?;

    if c != c_dec {
        return Err(eyre!("Expected {}, got {}", c, c_dec));
    }

    Ok(())
}

async fn test_encrypt_decrypt_uint_256(fhe: FheContract) -> Result<()> {
    let value = U256::from(42);
    let cipher = fhe.encrypt_uint_256(value).gas(GAS_PRICE).call().await?;
    let plain = fhe.decrypt_uint_256(cipher).gas(GAS_PRICE).call().await?;

    if plain != value {
        return Err(eyre!("Expected {}, got {}", value, plain));
    }

    Ok(())
}

async fn test_reencrypt_uint_256(fhe: FheContract) -> Result<()> {
    let (pub_key, priv_key) = generate_keys().unwrap();

    let value = U256::from(42);
    let cipher = fhe.encrypt_uint_256(value).gas(GAS_PRICE).call().await?;
    let cipher2 = fhe
        .reencrypt_uint_256(Bytes::from(pack_one_argument(&pub_key)), cipher)
        .gas(GAS_PRICE)
        .call()
        .await?;
    let plain: Unsigned256 = RUNTIME
        .decrypt(
            &unpack_one_argument(&cipher2).map_err(|_| eyre!("unpacking failed"))?,
            &priv_key,
        )
        .map_err(|_| eyre!("decryption failed"))?;
    let plain = convert_unsigned256_to_u256(plain);

    if plain != value {
        return Err(eyre!("Expected {}, got {}", value, plain));
    }

    Ok(())
}

async fn test_refresh_uint_256(fhe: FheContract) -> Result<()> {
    let value = U256::from(42);
    let cipher = fhe.encrypt_uint_256(value).gas(GAS_PRICE).call().await?;
    let cipher2 = fhe.refresh_uint_256(cipher).gas(GAS_PRICE).call().await?;
    let plain = fhe.decrypt_uint_256(cipher2).gas(GAS_PRICE).call().await?;

    if plain != value {
        return Err(eyre!("Expected {}, got {}", value, plain));
    }

    Ok(())
}

/** u64 tests ***************************************************************/

async fn test_add_uint_64_enc_enc(fhe: FheContract) -> Result<()> {
    let a = 1234u64;
    let b = 62u64;
    let c = a + b;

    let a_enc = fhe.encrypt_uint_64(a).gas(GAS_PRICE).call().await?;
    let b_enc = fhe.encrypt_uint_64(b).gas(GAS_PRICE).call().await?;

    let c_enc = fhe
        .add_uint_64_enc_enc(
            fhe.network_public_key().gas(GAS_PRICE).call().await?,
            a_enc,
            b_enc,
        )
        .gas(GAS_PRICE)
        .call()
        .await?;
    let c_dec = fhe.decrypt_uint_64(c_enc).gas(GAS_PRICE).call().await?;

    if c != c_dec {
        return Err(eyre!("Expected {}, got {}", c, c_dec));
    }

    Ok(())
}

async fn test_add_uint_64_enc_plain(fhe: FheContract) -> Result<()> {
    let a = 1234u64;
    let b = 62u64;
    let c = a + b;

    let a_enc = fhe.encrypt_uint_64(a).gas(GAS_PRICE).call().await?;

    let c_enc = fhe
        .add_uint_64_enc_plain(
            fhe.network_public_key().gas(GAS_PRICE).call().await?,
            a_enc,
            b,
        )
        .gas(GAS_PRICE)
        .call()
        .await?;
    let c_dec = fhe.decrypt_uint_64(c_enc).gas(GAS_PRICE).call().await?;

    if c != c_dec {
        return Err(eyre!("Expected {}, got {}", c, c_dec));
    }

    Ok(())
}

async fn test_add_uint_64_plain_enc(fhe: FheContract) -> Result<()> {
    let a = 1234u64;
    let b = 62u64;
    let c = a + b;

    let b_enc = fhe.encrypt_uint_64(b).gas(GAS_PRICE).call().await?;

    let c_enc = fhe
        .add_uint_64_plain_enc(
            fhe.network_public_key().gas(GAS_PRICE).call().await?,
            a,
            b_enc,
        )
        .gas(GAS_PRICE)
        .call()
        .await?;
    let c_dec = fhe.decrypt_uint_64(c_enc).gas(GAS_PRICE).call().await?;

    if c != c_dec {
        return Err(eyre!("Expected {}, got {}", c, c_dec));
    }

    Ok(())
}

async fn test_subtract_uint_64_enc_enc(fhe: FheContract) -> Result<()> {
    let a = 1234u64;
    let b = 62u64;
    let c = a - b;

    let a_enc = fhe.encrypt_uint_64(a).gas(GAS_PRICE).call().await?;
    let b_enc = fhe.encrypt_uint_64(b).gas(GAS_PRICE).call().await?;

    let c_enc = fhe
        .subtract_uint_64_enc_enc(
            fhe.network_public_key().gas(GAS_PRICE).call().await?,
            a_enc,
            b_enc,
        )
        .gas(GAS_PRICE)
        .call()
        .await?;
    let c_dec = fhe.decrypt_uint_64(c_enc).gas(GAS_PRICE).call().await?;

    if c != c_dec {
        return Err(eyre!("Expected {}, got {}", c, c_dec));
    }

    Ok(())
}

async fn test_subtract_uint_64_enc_plain(fhe: FheContract) -> Result<()> {
    let a = 1234u64;
    let b = 62u64;
    let c = a - b;

    let a_enc = fhe.encrypt_uint_64(a).gas(GAS_PRICE).call().await?;

    let c_enc = fhe
        .subtract_uint_64_enc_plain(
            fhe.network_public_key().gas(GAS_PRICE).call().await?,
            a_enc,
            b,
        )
        .gas(GAS_PRICE)
        .call()
        .await?;
    let c_dec = fhe.decrypt_uint_64(c_enc).gas(GAS_PRICE).call().await?;

    if c != c_dec {
        return Err(eyre!("Expected {}, got {}", c, c_dec));
    }

    Ok(())
}

async fn test_subtract_uint_64_plain_enc(fhe: FheContract) -> Result<()> {
    let a = 1234u64;
    let b = 62u64;
    let c = a - b;

    let b_enc = fhe.encrypt_uint_64(b).gas(GAS_PRICE).call().await?;

    let c_enc = fhe
        .subtract_uint_64_plain_enc(
            fhe.network_public_key().gas(GAS_PRICE).call().await?,
            a,
            b_enc,
        )
        .gas(GAS_PRICE)
        .call()
        .await?;
    let c_dec = fhe.decrypt_uint_64(c_enc).gas(GAS_PRICE).call().await?;

    if c != c_dec {
        return Err(eyre!("Expected {}, got {}", c, c_dec));
    }

    Ok(())
}

async fn test_multiply_uint_64_enc_enc(fhe: FheContract) -> Result<()> {
    let a = 1234u64;
    let b = 62u64;
    let c = a * b;

    let a_enc = fhe.encrypt_uint_64(a).gas(GAS_PRICE).call().await?;
    let b_enc = fhe.encrypt_uint_64(b).gas(GAS_PRICE).call().await?;

    let c_enc = fhe
        .multiply_uint_64_enc_enc(
            fhe.network_public_key().gas(GAS_PRICE).call().await?,
            a_enc,
            b_enc,
        )
        .gas(GAS_PRICE)
        .call()
        .await?;
    let c_dec = fhe.decrypt_uint_64(c_enc).gas(GAS_PRICE).call().await?;

    if c != c_dec {
        return Err(eyre!("Expected {}, got {}", c, c_dec));
    }

    Ok(())
}

async fn test_multiply_uint_64_enc_plain(fhe: FheContract) -> Result<()> {
    let a = 1234u64;
    let b = 62u64;
    let c = a * b;

    let a_enc = fhe.encrypt_uint_64(a).gas(GAS_PRICE).call().await?;

    let c_enc = fhe
        .multiply_uint_64_enc_plain(
            fhe.network_public_key().gas(GAS_PRICE).call().await?,
            a_enc,
            b,
        )
        .gas(GAS_PRICE)
        .call()
        .await?;
    let c_dec = fhe.decrypt_uint_64(c_enc).gas(GAS_PRICE).call().await?;

    if c != c_dec {
        return Err(eyre!("Expected {}, got {}", c, c_dec));
    }

    Ok(())
}

async fn test_multiply_uint_64_plain_enc(fhe: FheContract) -> Result<()> {
    let a = 1234u64;
    let b = 62u64;
    let c = a * b;

    let b_enc = fhe.encrypt_uint_64(b).gas(GAS_PRICE).call().await?;

    let c_enc = fhe
        .multiply_uint_64_plain_enc(
            fhe.network_public_key().gas(GAS_PRICE).call().await?,
            a,
            b_enc,
        )
        .gas(GAS_PRICE)
        .call()
        .await?;
    let c_dec = fhe.decrypt_uint_64(c_enc).gas(GAS_PRICE).call().await?;

    if c != c_dec {
        return Err(eyre!("Expected {}, got {}", c, c_dec));
    }

    Ok(())
}

async fn test_encrypt_decrypt_uint_64(fhe: FheContract) -> Result<()> {
    let value = 42u64;
    let cipher = fhe.encrypt_uint_64(value).gas(GAS_PRICE).call().await?;
    let plain = fhe.decrypt_uint_64(cipher).gas(GAS_PRICE).call().await?;

    if plain != value {
        return Err(eyre!("Expected {}, got {}", value, plain));
    }

    Ok(())
}

async fn test_reencrypt_uint_64(fhe: FheContract) -> Result<()> {
    let (pub_key, priv_key) = generate_keys().unwrap();

    let value = 42u64;
    let cipher = fhe.encrypt_uint_64(value).gas(GAS_PRICE).call().await?;
    let cipher2 = fhe
        .reencrypt_uint_64(Bytes::from(pack_one_argument(&pub_key)), cipher)
        .gas(GAS_PRICE)
        .call()
        .await?;

    let plain: Unsigned64 = RUNTIME
        .decrypt(
            &unpack_one_argument(&cipher2).map_err(|_| eyre!("unpacking failed"))?,
            &priv_key,
        )
        .map_err(|_| eyre!("decryption failed"))?;

    if plain != Unsigned64::from(value) {
        return Err(eyre!("Expected {}, got {}", value, plain));
    }

    Ok(())
}

async fn test_refresh_uint_64(fhe: FheContract) -> Result<()> {
    let value = 42u64;
    let cipher = fhe.encrypt_uint_64(value).gas(GAS_PRICE).call().await?;
    let cipher2 = fhe.refresh_uint_64(cipher).gas(GAS_PRICE).call().await?;
    let plain = fhe.decrypt_uint_64(cipher2).gas(GAS_PRICE).call().await?;

    if plain != value {
        return Err(eyre!("Expected {}, got {}", value, plain));
    }

    Ok(())
}

/** i64 tests ***************************************************************/

async fn test_add_int_64_enc_enc(fhe: FheContract) -> Result<()> {
    let a = 1234i64;
    let b = 62i64;
    let c = a + b;

    let a_enc = fhe.encrypt_int_64(a).gas(GAS_PRICE).call().await?;
    let b_enc = fhe.encrypt_int_64(b).gas(GAS_PRICE).call().await?;

    let c_enc = fhe
        .add_int_64_enc_enc(
            fhe.network_public_key().gas(GAS_PRICE).call().await?,
            a_enc,
            b_enc,
        )
        .gas(GAS_PRICE)
        .call()
        .await?;
    let c_dec = fhe.decrypt_int_64(c_enc).gas(GAS_PRICE).call().await?;

    if c != c_dec {
        return Err(eyre!("Expected {}, got {}", c, c_dec));
    }

    Ok(())
}

async fn test_add_int_64_enc_plain(fhe: FheContract) -> Result<()> {
    let a = 1234i64;
    let b = 62i64;
    let c = a + b;

    let a_enc = fhe.encrypt_int_64(a).gas(GAS_PRICE).call().await?;

    let c_enc = fhe
        .add_int_64_enc_plain(
            fhe.network_public_key().gas(GAS_PRICE).call().await?,
            a_enc,
            b,
        )
        .gas(GAS_PRICE)
        .call()
        .await?;
    let c_dec = fhe.decrypt_int_64(c_enc).gas(GAS_PRICE).call().await?;

    if c != c_dec {
        return Err(eyre!("Expected {}, got {}", c, c_dec));
    }

    Ok(())
}

async fn test_add_int_64_plain_enc(fhe: FheContract) -> Result<()> {
    let a = 1234i64;
    let b = 62i64;
    let c = a + b;

    let b_enc = fhe.encrypt_int_64(b).gas(GAS_PRICE).call().await?;

    let c_enc = fhe
        .add_int_64_plain_enc(
            fhe.network_public_key().gas(GAS_PRICE).call().await?,
            a,
            b_enc,
        )
        .gas(GAS_PRICE)
        .call()
        .await?;
    let c_dec = fhe.decrypt_int_64(c_enc).gas(GAS_PRICE).call().await?;

    if c != c_dec {
        return Err(eyre!("Expected {}, got {}", c, c_dec));
    }

    Ok(())
}

async fn test_subtract_int_64_enc_enc(fhe: FheContract) -> Result<()> {
    let a = 1234i64;
    let b = 62i64;
    let c = a - b;

    let a_enc = fhe.encrypt_int_64(a).gas(GAS_PRICE).call().await?;
    let b_enc = fhe.encrypt_int_64(b).gas(GAS_PRICE).call().await?;

    let c_enc = fhe
        .subtract_int_64_enc_enc(
            fhe.network_public_key().gas(GAS_PRICE).call().await?,
            a_enc,
            b_enc,
        )
        .gas(GAS_PRICE)
        .call()
        .await?;
    let c_dec = fhe.decrypt_int_64(c_enc).gas(GAS_PRICE).call().await?;

    if c != c_dec {
        return Err(eyre!("Expected {}, got {}", c, c_dec));
    }

    Ok(())
}

async fn test_subtract_int_64_enc_plain(fhe: FheContract) -> Result<()> {
    let a = 1234i64;
    let b = 62i64;
    let c = a - b;

    let a_enc = fhe.encrypt_int_64(a).gas(GAS_PRICE).call().await?;

    let c_enc = fhe
        .subtract_int_64_enc_plain(
            fhe.network_public_key().gas(GAS_PRICE).call().await?,
            a_enc,
            b,
        )
        .gas(GAS_PRICE)
        .call()
        .await?;
    let c_dec = fhe.decrypt_int_64(c_enc).gas(GAS_PRICE).call().await?;

    if c != c_dec {
        return Err(eyre!("Expected {}, got {}", c, c_dec));
    }

    Ok(())
}

async fn test_subtract_int_64_plain_enc(fhe: FheContract) -> Result<()> {
    let a = 1234i64;
    let b = 62i64;
    let c = a - b;

    let b_enc = fhe.encrypt_int_64(b).gas(GAS_PRICE).call().await?;

    let c_enc = fhe
        .subtract_int_64_plain_enc(
            fhe.network_public_key().gas(GAS_PRICE).call().await?,
            a,
            b_enc,
        )
        .gas(GAS_PRICE)
        .call()
        .await?;
    let c_dec = fhe.decrypt_int_64(c_enc).gas(GAS_PRICE).call().await?;

    if c != c_dec {
        return Err(eyre!("Expected {}, got {}", c, c_dec));
    }

    Ok(())
}

async fn test_multiply_int_64_enc_enc(fhe: FheContract) -> Result<()> {
    let a = 1234i64;
    let b = 62i64;
    let c = a * b;

    let a_enc = fhe.encrypt_int_64(a).gas(GAS_PRICE).call().await?;
    let b_enc = fhe.encrypt_int_64(b).gas(GAS_PRICE).call().await?;

    let c_enc = fhe
        .multiply_int_64_enc_enc(
            fhe.network_public_key().gas(GAS_PRICE).call().await?,
            a_enc,
            b_enc,
        )
        .gas(GAS_PRICE)
        .call()
        .await?;
    let c_dec = fhe.decrypt_int_64(c_enc).gas(GAS_PRICE).call().await?;

    if c != c_dec {
        return Err(eyre!("Expected {}, got {}", c, c_dec));
    }

    Ok(())
}

async fn test_multiply_int_64_enc_plain(fhe: FheContract) -> Result<()> {
    let a = 1234i64;
    let b = 62i64;
    let c = a * b;

    let a_enc = fhe.encrypt_int_64(a).gas(GAS_PRICE).call().await?;

    let c_enc = fhe
        .multiply_int_64_enc_plain(
            fhe.network_public_key().gas(GAS_PRICE).call().await?,
            a_enc,
            b,
        )
        .gas(GAS_PRICE)
        .call()
        .await?;
    let c_dec = fhe.decrypt_int_64(c_enc).gas(GAS_PRICE).call().await?;

    if c != c_dec {
        return Err(eyre!("Expected {}, got {}", c, c_dec));
    }

    Ok(())
}

async fn test_multiply_int_64_plain_enc(fhe: FheContract) -> Result<()> {
    let a = 1234i64;
    let b = 62i64;
    let c = a * b;

    let b_enc = fhe.encrypt_int_64(b).gas(GAS_PRICE).call().await?;

    let c_enc = fhe
        .multiply_int_64_plain_enc(
            fhe.network_public_key().gas(GAS_PRICE).call().await?,
            a,
            b_enc,
        )
        .gas(GAS_PRICE)
        .call()
        .await?;
    let c_dec = fhe.decrypt_int_64(c_enc).gas(GAS_PRICE).call().await?;

    if c != c_dec {
        return Err(eyre!("Expected {}, got {}", c, c_dec));
    }

    Ok(())
}

async fn test_encrypt_decrypt_int_64(fhe: FheContract) -> Result<()> {
    let value = -42i64;
    let cipher = fhe.encrypt_int_64(value).gas(GAS_PRICE).call().await?;
    let plain = fhe.decrypt_int_64(cipher).gas(GAS_PRICE).call().await?;

    if plain != value {
        return Err(eyre!("Expected {}, got {}", value, plain));
    }

    Ok(())
}

async fn test_reencrypt_int_64(fhe: FheContract) -> Result<()> {
    let (pub_key, priv_key) = generate_keys().unwrap();

    let value = -42i64;
    let cipher = fhe.encrypt_int_64(value).gas(GAS_PRICE).call().await?;
    let cipher2 = fhe
        .reencrypt_int_64(Bytes::from(pack_one_argument(&pub_key)), cipher)
        .gas(GAS_PRICE)
        .call()
        .await?;

    let plain: Signed = RUNTIME
        .decrypt(
            &unpack_one_argument(&cipher2).map_err(|_| eyre!("unpacking failed"))?,
            &priv_key,
        )
        .map_err(|_| eyre!("decryption failed"))?;

    if plain != Signed::from(value) {
        return Err(eyre!("Expected {}, got {}", value, plain));
    }

    Ok(())
}

async fn test_refresh_int_64(fhe: FheContract) -> Result<()> {
    let value = -42i64;
    let cipher = fhe.encrypt_int_64(value).gas(GAS_PRICE).call().await?;
    let cipher2 = fhe.refresh_int_64(cipher).gas(GAS_PRICE).call().await?;
    let plain = fhe.decrypt_int_64(cipher2).gas(GAS_PRICE).call().await?;

    if plain != value {
        return Err(eyre!("Expected {}, got {}", value, plain));
    }

    Ok(())
}

/** frac64 tests ************************************************************/

async fn test_add_frac_64_enc_enc(fhe: FheContract) -> Result<()> {
    let a = 1234f64;
    let b = 62f64;
    let c = a + b;

    let a_enc = fhe
        .encrypt_frac_64(a.to_be_bytes())
        .gas(GAS_PRICE)
        .call()
        .await?;
    let b_enc = fhe
        .encrypt_frac_64(b.to_be_bytes())
        .gas(GAS_PRICE)
        .call()
        .await?;

    let c_enc = fhe
        .add_frac_64_enc_enc(
            fhe.network_public_key().gas(GAS_PRICE).call().await?,
            a_enc,
            b_enc,
        )
        .gas(GAS_PRICE)
        .call()
        .await?;
    let c_dec = fhe.decrypt_frac_64(c_enc).gas(GAS_PRICE).call().await?;

    if c != f64::from_be_bytes(c_dec) {
        return Err(eyre!("Expected {}, got {}", c, f64::from_be_bytes(c_dec)));
    }

    Ok(())
}

async fn test_add_frac_64_enc_plain(fhe: FheContract) -> Result<()> {
    let a = 1234f64;
    let b = 62f64;
    let c = a + b;

    let a_enc = fhe
        .encrypt_frac_64(a.to_be_bytes())
        .gas(GAS_PRICE)
        .call()
        .await?;

    let c_enc = fhe
        .add_frac_64_enc_plain(
            fhe.network_public_key().gas(GAS_PRICE).call().await?,
            a_enc,
            b.to_be_bytes(),
        )
        .gas(GAS_PRICE)
        .call()
        .await?;
    let c_dec = fhe.decrypt_frac_64(c_enc).gas(GAS_PRICE).call().await?;

    if c != f64::from_be_bytes(c_dec) {
        return Err(eyre!("Expected {}, got {}", c, f64::from_be_bytes(c_dec)));
    }

    Ok(())
}

async fn test_add_frac_64_plain_enc(fhe: FheContract) -> Result<()> {
    let a = 1234f64;
    let b = 62f64;
    let c = a + b;

    let b_enc = fhe
        .encrypt_frac_64(b.to_be_bytes())
        .gas(GAS_PRICE)
        .call()
        .await?;

    let c_enc = fhe
        .add_frac_64_plain_enc(
            fhe.network_public_key().gas(GAS_PRICE).call().await?,
            a.to_be_bytes(),
            b_enc,
        )
        .gas(GAS_PRICE)
        .call()
        .await?;
    let c_dec = fhe.decrypt_frac_64(c_enc).gas(GAS_PRICE).call().await?;

    if c != f64::from_be_bytes(c_dec) {
        return Err(eyre!("Expected {}, got {}", c, f64::from_be_bytes(c_dec)));
    }

    Ok(())
}

async fn test_subtract_frac_64_enc_enc(fhe: FheContract) -> Result<()> {
    let a = 1234f64;
    let b = 62f64;
    let c = a - b;

    let a_enc = fhe
        .encrypt_frac_64(a.to_be_bytes())
        .gas(GAS_PRICE)
        .call()
        .await?;
    let b_enc = fhe
        .encrypt_frac_64(b.to_be_bytes())
        .gas(GAS_PRICE)
        .call()
        .await?;

    let c_enc = fhe
        .subtract_frac_64_enc_enc(
            fhe.network_public_key().gas(GAS_PRICE).call().await?,
            a_enc,
            b_enc,
        )
        .gas(GAS_PRICE)
        .call()
        .await?;
    let c_dec = fhe.decrypt_frac_64(c_enc).gas(GAS_PRICE).call().await?;

    if c != f64::from_be_bytes(c_dec) {
        return Err(eyre!("Expected {}, got {}", c, f64::from_be_bytes(c_dec)));
    }

    Ok(())
}

async fn test_subtract_frac_64_enc_plain(fhe: FheContract) -> Result<()> {
    let a = 1234f64;
    let b = 62f64;
    let c = a - b;

    let a_enc = fhe
        .encrypt_frac_64(a.to_be_bytes())
        .gas(GAS_PRICE)
        .call()
        .await?;

    let c_enc = fhe
        .subtract_frac_64_enc_plain(
            fhe.network_public_key().gas(GAS_PRICE).call().await?,
            a_enc,
            b.to_be_bytes(),
        )
        .gas(GAS_PRICE)
        .call()
        .await?;
    let c_dec = fhe.decrypt_frac_64(c_enc).gas(GAS_PRICE).call().await?;

    if c != f64::from_be_bytes(c_dec) {
        return Err(eyre!("Expected {}, got {}", c, f64::from_be_bytes(c_dec)));
    }

    Ok(())
}

async fn test_subtract_frac_64_plain_enc(fhe: FheContract) -> Result<()> {
    let a = 1234f64;
    let b = 62f64;
    let c = a - b;

    let b_enc = fhe
        .encrypt_frac_64(b.to_be_bytes())
        .gas(GAS_PRICE)
        .call()
        .await?;

    let c_enc = fhe
        .subtract_frac_64_plain_enc(
            fhe.network_public_key().gas(GAS_PRICE).call().await?,
            a.to_be_bytes(),
            b_enc,
        )
        .gas(GAS_PRICE)
        .call()
        .await?;
    let c_dec = fhe.decrypt_frac_64(c_enc).gas(GAS_PRICE).call().await?;

    if c != f64::from_be_bytes(c_dec) {
        return Err(eyre!("Expected {}, got {}", c, f64::from_be_bytes(c_dec)));
    }

    Ok(())
}

async fn test_multiply_frac_64_enc_enc(fhe: FheContract) -> Result<()> {
    let a = 1234f64;
    let b = 62f64;
    let c = a * b;

    let a_enc = fhe
        .encrypt_frac_64(a.to_be_bytes())
        .gas(GAS_PRICE)
        .call()
        .await?;
    let b_enc = fhe
        .encrypt_frac_64(b.to_be_bytes())
        .gas(GAS_PRICE)
        .call()
        .await?;

    let c_enc = fhe
        .multiply_frac_64_enc_enc(
            fhe.network_public_key().gas(GAS_PRICE).call().await?,
            a_enc,
            b_enc,
        )
        .gas(GAS_PRICE)
        .call()
        .await?;
    let c_dec = fhe.decrypt_frac_64(c_enc).gas(GAS_PRICE).call().await?;

    if c != f64::from_be_bytes(c_dec) {
        return Err(eyre!("Expected {}, got {}", c, f64::from_be_bytes(c_dec)));
    }

    Ok(())
}

async fn test_multiply_frac_64_enc_plain(fhe: FheContract) -> Result<()> {
    let a = 1234f64;
    let b = 62f64;
    let c = a * b;

    let a_enc = fhe
        .encrypt_frac_64(a.to_be_bytes())
        .gas(GAS_PRICE)
        .call()
        .await?;

    let c_enc = fhe
        .multiply_frac_64_enc_plain(
            fhe.network_public_key().gas(GAS_PRICE).call().await?,
            a_enc,
            b.to_be_bytes(),
        )
        .gas(GAS_PRICE)
        .call()
        .await?;
    let c_dec = fhe.decrypt_frac_64(c_enc).gas(GAS_PRICE).call().await?;

    if c != f64::from_be_bytes(c_dec) {
        return Err(eyre!("Expected {}, got {}", c, f64::from_be_bytes(c_dec)));
    }

    Ok(())
}

async fn test_multiply_frac_64_plain_enc(fhe: FheContract) -> Result<()> {
    let a = 1234f64;
    let b = 62f64;
    let c = a * b;

    let b_enc = fhe
        .encrypt_frac_64(b.to_be_bytes())
        .gas(GAS_PRICE)
        .call()
        .await?;

    let c_enc = fhe
        .multiply_frac_64_plain_enc(
            fhe.network_public_key().gas(GAS_PRICE).call().await?,
            a.to_be_bytes(),
            b_enc,
        )
        .gas(GAS_PRICE)
        .call()
        .await?;
    let c_dec = fhe.decrypt_frac_64(c_enc).gas(GAS_PRICE).call().await?;

    if c != f64::from_be_bytes(c_dec) {
        return Err(eyre!("Expected {}, got {}", c, f64::from_be_bytes(c_dec)));
    }

    Ok(())
}

async fn test_encrypt_decrypt_frac_64(fhe: FheContract) -> Result<()> {
    let value = 42.42f64.to_be_bytes();
    let cipher = fhe.encrypt_frac_64(value).gas(GAS_PRICE).call().await?;
    let plain = fhe.decrypt_frac_64(cipher).gas(GAS_PRICE).call().await?;

    if plain != value {
        return Err(eyre!("Expected {:?}, got {:?}", value, plain));
    }

    Ok(())
}

async fn test_reencrypt_frac_64(fhe: FheContract) -> Result<()> {
    let (pub_key, priv_key) = generate_keys().unwrap();

    let value = 42.42f64.to_be_bytes();
    let cipher = fhe.encrypt_frac_64(value).gas(GAS_PRICE).call().await?;
    let cipher2 = fhe
        .reencrypt_frac_64(Bytes::from(pack_one_argument(&pub_key)), cipher)
        .gas(GAS_PRICE)
        .call()
        .await?;

    let plain: Fractional<64> = RUNTIME
        .decrypt(
            &unpack_one_argument(&cipher2).map_err(|_| eyre!("unpacking failed"))?,
            &priv_key,
        )
        .map_err(|_| eyre!("decryption failed"))?;

    if plain.to_be_bytes() != value {
        return Err(eyre!("Expected {:?}, got {:?}", value, plain));
    }

    Ok(())
}

async fn test_refresh_frac_64(fhe: FheContract) -> Result<()> {
    let value = 42.42f64.to_be_bytes();
    let cipher = fhe.encrypt_frac_64(value).gas(GAS_PRICE).call().await?;
    let cipher2 = fhe.refresh_frac_64(cipher).gas(GAS_PRICE).call().await?;
    let plain = fhe.decrypt_frac_64(cipher2).gas(GAS_PRICE).call().await?;

    if plain != value {
        return Err(eyre!("Expected {:?}, got {:?}", value, plain));
    }

    Ok(())
}
