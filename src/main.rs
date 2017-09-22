#[macro_use] extern crate clap;
#[macro_use] extern crate error_chain;
extern crate serde;
#[macro_use] extern crate serde_derive;
#[macro_use] extern crate serde_json;
extern crate rpassword;
extern crate ring;
extern crate reqwest;
extern crate hex;

use hex::{FromHex, ToHex};

use std::path;
use std::fs;
use std::io::{Read, Write};

mod cli;
mod crypto;
mod errors;
use errors::*;


pub const APP_NAME: &'static str = "Transfer";
pub const APP_VERSION: &'static str = crate_version!();
pub const HOST: &'static str = "http://localhost:3000";


/// `/api/upload/init` response
#[derive(Debug, Deserialize)]
struct UploadResp {
    key: String,
    response_url: String,
}

/// `/api/download/init` response
#[derive(Debug, Deserialize)]
struct DownloadInitResp {
    nonce: String,
}

/// `/api/download/name` response
#[derive(Debug, Deserialize)]
struct ConfirmResp {
    file_name: String,
}


/// Prompt user for `access` and `encryption` passwords
///
/// Returns `(access, encryption)` or an `Error` if either confirmation
/// passwords do not match
fn prompt_passwords() -> Result<(Vec<u8>, Vec<u8>)> {
    let access_pass =           rpassword::prompt_password_stdout("Access-Password >> ")?;
    let access_pass_confirm =   rpassword::prompt_password_stdout("Access-Password (confirm) >> ")?;
    if access_pass != access_pass_confirm { bail!("Access passwords do not match!") }
    let access_pass = access_pass.as_bytes().to_vec();

    let encrypt_pass =          rpassword::prompt_password_stdout("Encryption-Password >> ")?;
    let encrypt_pass_confirm =  rpassword::prompt_password_stdout("Encryption-Password (confirm) >> ")?;
    if encrypt_pass != encrypt_pass_confirm { bail!("Encryption passwords do not match!") }
    let encrypt_pass_hash = crypto::hash(encrypt_pass.as_bytes());
    Ok((access_pass, encrypt_pass_hash))
}


/// Try to get y/n confirmation for a prompt
fn confirm(msg: &str) -> Result<()> {
    print!("{}", msg);
    std::io::stdout().flush()?;
    let mut s = String::new();
    std::io::stdin().read_line(&mut s)?;
    let s = s.trim().to_lowercase();
    if s != "y" { bail!(ErrorKind::ConfirmationError("Unable to confirm file overwrite".to_string())) }
    Ok(())
}


/// Encrypt and upload a file
fn upload(file_path: &path::Path) -> Result<()> {
    let file_name = file_path.file_name()
        .and_then(std::ffi::OsStr::to_str)
        .map(String::from)
        .ok_or_else(|| ErrorKind::InvalidUtf8Path(format!("{:?}", file_path)))?;
    println!("Selected file: {:?}", file_path);

    let (access_pass, encrypt_pass_hash) = prompt_passwords()?;

    println!("Loading file...");
    let mut file = fs::File::open(&file_path)?;
    let file_size = file.metadata()?.len();
    let mut bytes = Vec::with_capacity(file_size as usize);
    file.read_to_end(&mut bytes)?;

    let file_hash = crypto::hash(&bytes);
    let nonce = crypto::rand_bytes(12)?;
    let client = reqwest::Client::new()?;

    println!("Initializing upload...");
    let upload_init_info = json!({
        "nonce": nonce.to_hex(),
        "file_name": &file_name,
        "file_size": file_size,
        "content_hash": file_hash.to_hex(),
        "access_password": access_pass.to_hex(),
    }).to_string();
    let url = format!("{}/api/upload/init", HOST);
    let resp = client.post(&url)?
        .header(reqwest::header::ContentType::json())
        .body(upload_init_info)
        .send()?;
    let resp = resp.error_for_status()?.json::<UploadResp>()?;

    println!("Received identification key: {}", resp.key);
    println!("Encrypting data...");
    let bytes = crypto::encrypt(&bytes, &nonce, &encrypt_pass_hash)?;

    println!("Uploading encrypted data...");
    let url = format!("{}{}?key={}", HOST, resp.response_url, resp.key);
    client.post(&url)?
        .header(reqwest::header::ContentType::plaintext())
        .body(bytes.to_hex())
        .send()?
        .error_for_status()?
        .json::<serde_json::Value>()?;
    println!("Download available at {}/#/download?key={}", HOST, resp.key);
    Ok(())
}


fn download(key: &str, out_path: &path::Path) -> Result<()> {
    println!("Downloading key: {}", key);
    let (access_pass, encrypt_pass_hash) = prompt_passwords()?;

    let client = reqwest::Client::new()?;

    println!("Fetching metadata...");
    let download_access_params = json!({
        "key": &key,
        "access_password": access_pass.to_hex(),
    }).to_string();
    let url = format!("{}/api/download/init", HOST);
    let init_resp = client.post(&url)?
        .header(reqwest::header::ContentType::json())
        .body(download_access_params.clone())
        .send()?
        .error_for_status()?
        .json::<DownloadInitResp>()?;

    println!("Downloading encrypted bytes...");
    let url = format!("{}/api/download?key={}", HOST, key);
    let mut bytes_resp = client.post(&url)?
        .header(reqwest::header::ContentType::json())
        .body(download_access_params.clone())
        .send()?
        .error_for_status()?;
    let mut enc_bytes = Vec::new();
    bytes_resp.read_to_end(&mut enc_bytes)?;

    let mut enc_bytes = Vec::from_hex(enc_bytes)?;
    let nonce = Vec::from_hex(&init_resp.nonce)?;

    println!("Decrypting data...");
    let bytes = crypto::decrypt(&mut enc_bytes, &nonce, &encrypt_pass_hash)?;
    let hash = crypto::hash(bytes);

    println!("Confirming content hash and fetching file-name...");
    let confirm_params = json!({
        "key": &key,
        "hash": hash.to_hex(),
    }).to_string();
    let url = format!("{}/api/download/name", HOST);
    let name_resp = client.post(&url)?
        .header(reqwest::header::ContentType::json())
        .body(confirm_params)
        .send()?
        .error_for_status()?.json::<ConfirmResp>()?;

    let out_path = if out_path.is_dir() { out_path.join(name_resp.file_name) } else { out_path.to_owned() };
    println!("Saving decrypted bytes to: {:?}", out_path);
    if out_path.exists() {
        confirm("Destination file already exists. Continue and overwrite? [y/n] ")?;
    }
    let mut file = fs::File::create(out_path)?;
    file.write_all(bytes)?;
    println!("Success!");
    Ok(())
}


fn run() -> Result<()> {
    let matches = cli::build_cli().get_matches();
    match matches.subcommand() {
        ("upload", Some(matches)) => {
            let file_path = matches.value_of("file_path").unwrap();
            let file_path = path::PathBuf::from(file_path);
            if !file_path.exists() {
                bail!("Invalid file path: {:?}", file_path)
            }
            upload(&file_path)?;
        }
        ("download", Some(matches)) => {
            let key = matches.value_of("key").unwrap();
            let out_path = matches.value_of("out_path").unwrap_or(".");
            let out_path = path::PathBuf::from(out_path);
            download(key, &out_path)?;
        }
        _ => println!("no matches!"),
    }
    Ok(())
}


quick_main!(run);

