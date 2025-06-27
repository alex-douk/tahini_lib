use clap::Parser;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::env;
use std::fs;
use std::fs::File;
use std::fs::create_dir;
use std::io::Read;
use std::io::{self, BufRead, BufReader};
use std::path::{Path, PathBuf};

mod manifest_generation;

#[derive(Deserialize, Serialize)]
pub struct TahiniCertificate {
    service_name: String,
    policy_hash: PolicyHash,
    binary_hash: BinHash,
    signature: Signature,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
#[allow(unused)]
pub struct BinHash(String);

#[derive(Deserialize, Serialize, Debug, Clone)]
#[allow(unused)]
pub struct Signature(String);

#[derive(Deserialize, Serialize, Debug, Clone)]
#[allow(unused)]
pub struct PolicyHash(String);

fn retrieve_hash_from_file(policy_filename: &Path) -> io::Result<String> {
    let file = File::options().read(true).open(policy_filename)?;
    let first_line = std::io::BufReader::new(file).lines().next();
    match first_line {
        None => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "Policy hash for file {} was not found",
                policy_filename.to_str().unwrap()
            ),
        )),
        Some(hash_line) => Ok(hash_line?),
    }
}

fn match_policies_to_bin(
    policy_dir: &Path,
    target_binaries: Vec<PathBuf>,
) -> io::Result<HashMap<String, PolicyHash>> {
    let mut hashes = HashMap::new();
    // let mut binaries = Vec::new();
    if policy_dir.exists() && policy_dir.is_dir() {
        for binaries in target_binaries.iter().map(|bin_path| bin_path.file_name()) {
            match binaries {
                None => return Ok(HashMap::new()),
                Some(bin_filename) => {
                    for entry in fs::read_dir(policy_dir)? {
                        let path = entry?.path();
                        let file_path = path.file_name();
                        match file_path {
                            None => continue,
                            Some(pol_fn) => {
                                let policy_filename = pol_fn.to_str().unwrap();
                                let assumed_pol_filename = format!(
                                    "{}_policy_hashes.json",
                                    bin_filename.to_str().unwrap()
                                );
                                if policy_filename == assumed_pol_filename {
                                    hashes.insert(
                                        bin_filename.to_str().unwrap().to_string(),
                                        PolicyHash(retrieve_hash_from_file(path.as_path())?),
                                    );
                                    println!("{}", policy_filename);
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    Ok(hashes)
}

fn is_executable(file: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    fs::metadata(file)
        .map(|m| m.is_file() && (m.permissions().mode() & 0o111) != 0)
        .unwrap_or(false)
}

fn find_binaries_in_target(target_dir: &Path) -> io::Result<Vec<PathBuf>> {
    let mut binaries = Vec::new();
    // let possible_dirs = vec![target_dir.join("debug"), target_dir.join("release")];

    let dir = target_dir.join("release");
    println!("Exploring dir {:?}", dir);
    // for dir in possible_dirs {
    if dir.exists() && dir.is_dir() {
        println!("Found target dir");
        for entry in fs::read_dir(&dir)? {
            let path = entry?.path();
            println!("Found entry {:?}", path);
            if is_executable(&path) {
                binaries.push(path);
            }
        }
        // }
    }
    Ok(binaries)
}

#[allow(unused)]
fn merge_maps(
    policy_map: HashMap<String, PolicyHash>,
    binary_map: HashMap<String, BinHash>,
) -> HashMap<String, (PolicyHash, BinHash)> {
    policy_map
        .iter()
        .filter_map(|(k, v1)| {
            binary_map
                .get(k)
                .map(|v2| (k.clone(), (v1.clone(), v2.clone())))
        })
        .collect()
}

#[allow(unused)]
fn hash_binaries(bin_paths: Vec<PathBuf>) -> io::Result<HashMap<String, BinHash>> {
    let mut map = HashMap::new();
    for binary in bin_paths {
        println!("Hashing binary {:?}", binary);
        let file = File::open(&binary)?;
        let mut reader = BufReader::new(file);
        let mut hasher = Sha256::new();
        let mut buffer = [0u8; 8192];

        loop {
            let bytes_read = reader.read(&mut buffer)?;
            if bytes_read == 0 {
                break;
            }
            hasher.update(&buffer[..bytes_read]);
        }

        let result = hasher.finalize();
        let bin_name = binary.file_name().unwrap().to_str().unwrap();
        map.insert(bin_name.to_string(), BinHash(hex::encode(result)));
    }
    Ok(map)
}

fn main() -> io::Result<()> {
    let args = CliArgs::parse();
    let project_root = args.project_folder;
    let target_dir = project_root.join("target");

    let key_path = args.signing_key_path;

    let skey = manifest_generation::get_signing_key(
        &key_path
    );

    let binaries = find_binaries_in_target(&target_dir)?;
    println!("Found {} binaries", binaries.len());

    let policy_dir = project_root.join("policy_hashes");

    let pols = match_policies_to_bin(&policy_dir, binaries.clone())?;
    let bin_hashes = hash_binaries(binaries)?;
    //
    let merged = merge_maps(pols, bin_hashes);

    let certificates: HashMap<_, _> = merged
        .into_iter()
        .map(|(bin_name, data)| {
            (
                bin_name.clone(),
                manifest_generation::gen_certificate(bin_name, data, &skey),
            )
        })
        .collect();

    fn format_filename(filename: &String) -> String {
        format!("{}_certificate.json", filename)
    }

    let certificates_dir = project_root.join("certificates");
    match create_dir(&certificates_dir) {
        Ok(_) => println!("Created certificates directory for the current project"),
        Err(_) => println!("Updating certificate directory"),
    }

    for (k, v) in certificates.iter() {
        let certif_file_path = certificates_dir.clone().join(format_filename(k));
        let file = File::create(certif_file_path)?;
        serde_json::to_writer_pretty(file, &v)?;
    }

    Ok(())
}

#[derive(clap::Parser)]
pub struct CliArgs {
    #[arg(short='p', long="project_folder")]
    project_folder: PathBuf,
    #[arg(short='k', long="signing_key_path")]
    signing_key_path: PathBuf
}
