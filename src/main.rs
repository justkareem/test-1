use clap::Parser;
use ed25519_dalek::{SigningKey, VerifyingKey};
use logfather::{Level, Logger};
use num_format::{Locale, ToFormattedString};
use rand::{rngs::OsRng};
use rayon::iter::{IntoParallelIterator, ParallelIterator};
use sha2::{Digest, Sha256};

use std::{
    sync::atomic::{AtomicBool, Ordering},
    time::Instant,
};

#[derive(Debug, Parser)]
#[command(name = "vanity-keypair")]
#[command(about = "Fast ed25519 keypair generator for Solana vanity addresses")]
pub struct Args {
    /// The target prefix for the pubkey
    #[clap(long)]
    pub prefix: Option<String>,

    /// The target suffix for the pubkey  
    #[clap(long)]
    pub suffix: Option<String>,

    /// Whether user cares about the case of the pubkey
    #[clap(long, default_value_t = false)]
    pub case_insensitive: bool,

    /// Optional log file
    #[clap(long)]
    pub logfile: Option<String>,

    /// Number of gpus to use for mining
    #[clap(long, default_value_t = 1)]
    #[cfg(feature = "gpu")]
    pub num_gpus: u32,

    /// Number of cpu threads to use for mining
    #[clap(long, default_value_t = 0)]
    pub num_cpus: u32,
}

static EXIT: AtomicBool = AtomicBool::new(false);

fn main() {
    rayon::ThreadPoolBuilder::new().build_global().unwrap();

    // Parse command line arguments
    let mut args = Args::parse();
    
    maybe_update_num_cpus(&mut args.num_cpus);
    let prefix = get_validated_prefix(&args);
    let suffix = get_validated_suffix(&args);

    // Initialize logger with optional logfile
    let mut logger = Logger::new();
    if let Some(ref logfile) = args.logfile {
        logger.file(true);
        logger.path(logfile);
    }

    // Slightly more compact log format
    logger.log_format("[{timestamp} {level}] {message}");
    logger.timestamp_format("%Y-%m-%d %H:%M:%S");
    logger.level(Level::Info);

    // Print resource usage
    logfather::info!("using {} threads", args.num_cpus);
    #[cfg(feature = "gpu")]
    logfather::info!("using {} gpus", args.num_gpus);
    logfather::info!("grinding ed25519 keypairs for direct wallet import");

    #[cfg(feature = "gpu")]
    let _gpu_threads: Vec<_> = (0..args.num_gpus)
        .map(move |gpu_index| {
            std::thread::Builder::new()
                .name(format!("gpu{gpu_index}"))
                .spawn(move || {
                    logfather::trace!("starting keypair gpu {gpu_index}");

                    let mut out = [0; 64]; // 32 bytes private key + 32 bytes public key
                    for iteration in 0_u64.. {
                        // Exit if a thread found a solution
                        if EXIT.load(Ordering::SeqCst) {
                            logfather::trace!("keypair gpu thread {gpu_index} exiting");
                            return;
                        }

                        // Generate new seed for this gpu & iteration
                        let seed = new_gpu_seed(gpu_index, iteration);
                        let timer = Instant::now();
                        unsafe {
                            vanity_keypair_round(gpu_index, seed.as_ref().as_ptr(), prefix.as_ptr(), suffix.as_ptr(), prefix.len() as u64, suffix.len() as u64, out.as_mut_ptr(), args.case_insensitive);
                        }
                        let time_sec = timer.elapsed().as_secs_f64();

                        // Check if we found a match
                        let private_key_bytes: [u8; 32] = out[..32].try_into().unwrap();
                        let public_key_bytes: [u8; 32] = out[32..].try_into().unwrap();
                        let count = u64::from_le_bytes([out[56], out[57], out[58], out[59], out[60], out[61], out[62], out[63]]);

                        // Only process if we got a valid result (non-zero count)
                        if count > 0 {
                            let pubkey = fd_bs58::encode_32(public_key_bytes);
                            let out_str_target_check = maybe_bs58_aware_lowercase(&pubkey, args.case_insensitive);

                            // Only log if it actually matches the target (GPU should have filtered this)
                            if out_str_target_check.starts_with(prefix) && out_str_target_check.ends_with(suffix) {
                                logfather::info!(
                                    "{} found in {:.3} seconds on gpu {gpu_index:>3}; {:>13} iters; {:>12} iters/sec",
                                    &pubkey,
                                    time_sec,
                                    count.to_formatted_string(&Locale::en),
                                    ((count as f64 / time_sec) as u64).to_formatted_string(&Locale::en)
                                );

                                let private_key_b58 = fd_bs58::encode_32(private_key_bytes);
                                logfather::info!("Public Key: {}", pubkey);
                                logfather::info!("Private Key (for Phantom/wallet import): {}", private_key_b58);
                                logfather::info!("Private Key Array: {:?}", private_key_bytes.to_vec());
                                EXIT.store(true, Ordering::SeqCst);
                                logfather::trace!("keypair gpu thread {gpu_index} exiting");
                                return;
                            }
                        }
                    }
                })
                .unwrap()
        })
        .collect();

    (0..args.num_cpus).into_par_iter().for_each(|i| {
        let timer = Instant::now();
        let mut count = 0_u64;

        loop {
            if EXIT.load(Ordering::Acquire) {
                return;
            }

            // Generate ed25519 keypair
            let signing_key = SigningKey::generate(&mut OsRng);
            let verifying_key = signing_key.verifying_key();
            let pubkey_bytes = verifying_key.to_bytes();
            let pubkey = fd_bs58::encode_32(pubkey_bytes);
            let out_str_target_check = maybe_bs58_aware_lowercase(&pubkey, args.case_insensitive);

            count += 1;

            // Did cpu find target?
            if out_str_target_check.starts_with(prefix) && out_str_target_check.ends_with(suffix) {
                let time_secs = timer.elapsed().as_secs_f64();
                let private_key_bytes = signing_key.to_bytes();
                let private_key_b58 = fd_bs58::encode_32(private_key_bytes);
                
                logfather::info!(
                    "cpu {} found target: {} in {:.3}s; {} attempts; {} attempts per second",
                    i,
                    pubkey,
                    time_secs,
                    count.to_formatted_string(&Locale::en),
                    ((count as f64 / time_secs) as u64).to_formatted_string(&Locale::en)
                );
                
                logfather::info!("Public Key: {}", pubkey);
                logfather::info!("Private Key (for Phantom/wallet import): {}", private_key_b58);
                logfather::info!("Private Key Array: {:?}", private_key_bytes.to_vec());

                EXIT.store(true, Ordering::Release);
                break;
            }
        }
    });
}

fn get_validated_prefix(args: &Args) -> &'static str {
    // Static string of BS58 characters
    const BS58_CHARS: &str = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

    if let Some(ref prefix) = args.prefix {
        for c in prefix.chars() {
            assert!(
                BS58_CHARS.contains(c),
                "your prefix contains invalid bs58: {}",
                c
            );
        }
        let prefix = maybe_bs58_aware_lowercase(&prefix, args.case_insensitive);
        return prefix.leak();
    }
    ""
}

fn get_validated_suffix(args: &Args) -> &'static str {
    // Static string of BS58 characters
    const BS58_CHARS: &str = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

    if let Some(ref suffix) = args.suffix {
        for c in suffix.chars() {
            assert!(
                BS58_CHARS.contains(c),
                "your suffix contains invalid bs58: {}",
                c
            );
        }
        let suffix = maybe_bs58_aware_lowercase(&suffix, args.case_insensitive);
        return suffix.leak();
    }
    ""
}

fn maybe_bs58_aware_lowercase(target: &str, case_insensitive: bool) -> String {
    // L is only char that shouldn't be converted to lowercase in case-insensitivity case
    const LOWERCASE_EXCEPTIONS: &str = "L";

    if case_insensitive {
        target
            .chars()
            .map(|c| {
                if LOWERCASE_EXCEPTIONS.contains(c) {
                    c
                } else {
                    c.to_ascii_lowercase()
                }
            })
            .collect::<String>()
    } else {
        target.to_string()
    }
}

#[cfg(feature = "gpu")]
extern "C" {
    pub fn vanity_keypair_round(
        gpu_id: u32,
        seed: *const u8,
        target: *const u8,
        suffix: *const u8,
        target_len: u64,
        suffix_len: u64,
        out: *mut u8,
        case_insensitive: bool,
    );
}

#[cfg(feature = "gpu")]
fn new_gpu_seed(gpu_id: u32, iteration: u64) -> [u8; 32] {
    Sha256::new()
        .chain_update(rand::random::<[u8; 32]>())
        .chain_update(gpu_id.to_le_bytes())
        .chain_update(iteration.to_le_bytes())
        .finalize()
        .into()
}

fn maybe_update_num_cpus(num_cpus: &mut u32) {
    if *num_cpus == 0 {
        *num_cpus = rayon::current_num_threads() as u32;
    }
}