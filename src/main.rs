#[macro_use] extern crate clap;
#[macro_use] extern crate error_chain;
extern crate serde;
#[macro_use] extern crate serde_derive;
#[macro_use] extern crate serde_json;
extern crate rpassword;
extern crate ring;
extern crate reqwest;
extern crate hex;
extern crate pbr;

use hex::{FromHex, ToHex};

use std::path;
use std::fs;
use std::io::{Read, BufRead, Write, Stdout, BufReader};

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
}

/// `/api/download/init` response
#[derive(Debug, Deserialize)]
struct DownloadInitResp {
    nonce: String,
    size: u64,
    download_key: String,
    confirm_key: String,
}

/// `/api/download/name` response
#[derive(Debug, Deserialize)]
struct ConfirmResp {
    file_name: String,
}

#[derive(Debug, Deserialize)]
struct ErrorResp {
    error: String,
}


/// Check a `reqwest::Response` status, bailing if it's not successful
macro_rules! unwrap_resp {
    ($resp:expr) => {
        if ! $resp.status().is_success() {
            let err = $resp.json::<ErrorResp>()?;
            bail!("{:?}: {:?}", $resp.status(), err.error)
        } else {
            $resp
        }
    }
}


/// Bytes wrapper
///
/// Wrapped bytes that display a progress bar while being read
struct UploadBytes {
    buf: Vec<u8>,
    size: usize,
    cursor: usize,
    progress: pbr::ProgressBar<Stdout>,
}
impl UploadBytes {
    fn new(bytes: Vec<u8>, pb: pbr::ProgressBar<Stdout>) -> Self {
        Self {
            size: bytes.len(),
            buf: bytes,
            cursor: 0,
            progress: pb,
        }
    }
}
impl Read for UploadBytes {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let buf_len = buf.len();
        let end = self.cursor + buf_len;
        let end = if end > self.size { self.size } else { end };
        let bytes_read = end - self.cursor;
        buf[..bytes_read].clone_from_slice(&self.buf[self.cursor..end]);
        self.cursor = end;
        self.progress.add(bytes_read as u64);
        Ok(bytes_read)
    }
}


/// Prompt user for `access` and `encryption` passwords
///
/// Returns `(access, encryption)` or an `Error` if either confirmation
/// passwords do not match
fn prompt_passwords(with_delete: bool) -> Result<(Vec<u8>, Vec<u8>, Option<Vec<u8>>)> {
    let access_pass =           rpassword::prompt_password_stdout("Access-Password >> ")?;
    let access_pass_confirm =   rpassword::prompt_password_stdout("Access-Password (confirm) >> ")?;
    if access_pass != access_pass_confirm { bail!("Access passwords do not match!") }
    let access_pass = access_pass.as_bytes().to_vec();

    let encrypt_pass =          rpassword::prompt_password_stdout("Encryption-Password >> ")?;
    let encrypt_pass_confirm =  rpassword::prompt_password_stdout("Encryption-Password (confirm) >> ")?;
    if encrypt_pass != encrypt_pass_confirm { bail!("Encryption passwords do not match!") }
    let encrypt_pass_hash = crypto::hash(encrypt_pass.as_bytes());

    let deletion_pass = {
        if with_delete {
            let pass = rpassword::prompt_password_stdout("Deletion-Password >> ")?;
            if pass.is_empty() { None } else {
                let confirm = rpassword::prompt_password_stdout("Deletion-Password (confirm) >> ")?;
                if pass != confirm { bail!("Deletion passwords do not match!") }
                Some(pass.as_bytes().to_vec())
            }
        } else {
            None
        }
    };
    Ok((access_pass, encrypt_pass_hash, deletion_pass))
}


/// Try to get y/n confirmation for a prompt
fn prompt(msg: &str) -> Result<String> {
    print!("{}", msg);
    std::io::stdout().flush()?;
    let mut s = String::new();
    std::io::stdin().read_line(&mut s)?;
    Ok(s.trim().to_lowercase())
}


/// Encrypt and upload a file
fn upload(file_path: &path::Path, download_limit: Option<u32>, lifespan: Option<u64>) -> Result<()> {
    let file_name = file_path.file_name()
        .and_then(std::ffi::OsStr::to_str)
        .map(String::from)
        .ok_or_else(|| ErrorKind::InvalidUtf8Path(format!("{:?}", file_path)))?;
    println!("Selected file: {:?}", file_path);
    println!("  Download limit: {}", download_limit.map(|n| n.to_string()).unwrap_or_else(|| "Server default".to_string()));
    println!("  Upload lifespan: {}", lifespan.map(|n| format!("{} seconds", n)).unwrap_or_else(|| "Server default".to_string()));

    let (access_pass, encrypt_pass_hash, deletion_pass) = prompt_passwords(true)?;

    println!("Loading file...");
    let mut file = fs::File::open(&file_path)?;
    let file_size = file.metadata()?.len();
    let mut bytes = Vec::with_capacity(file_size as usize);
    file.read_to_end(&mut bytes)?;

    let file_hash = crypto::hash(&bytes);
    let nonce = crypto::rand_bytes(12)?;

    println!("Encrypting data...");
    let bytes = crypto::encrypt(&bytes, &nonce, &encrypt_pass_hash)?;
    let upload_size = bytes.len();

    let client = reqwest::Client::new()?;

    println!("Initializing upload...");
    let upload_init_info = json!({
        "nonce": nonce.to_hex(),
        "file_name": &file_name,
        "size": upload_size,
        "content_hash": file_hash.to_hex(),
        "access_password": access_pass.to_hex(),
        "deletion_password": deletion_pass.map(|bytes| bytes.to_hex()),
        "download_limit": download_limit,
        "lifespan": lifespan,
    }).to_string();
    let url = format!("{}/api/upload/init", HOST);
    let mut resp = client.post(&url)?
        .header(reqwest::header::ContentType::json())
        .body(upload_init_info)
        .send()?;
    let resp = unwrap_resp!(resp).json::<UploadResp>()?;
    println!("Received identification key: {}", resp.key);

    println!("Uploading encrypted data...");
    let mut pb = pbr::ProgressBar::new(upload_size as u64);
    pb.set_units(pbr::Units::Bytes);
    pb.format("[=> ]");
    let upload_bytes = UploadBytes::new(bytes, pb);
    let url = format!("{}/api/upload?key={}", HOST, resp.key);
    let mut upload_resp = client.post(&url)?
        .header(reqwest::header::ContentType::octet_stream())
        .body(reqwest::Body::new(upload_bytes))
        .send()?;
    unwrap_resp!(upload_resp);
    println!("Download available at {}/#/download?key={}", HOST, resp.key);
    Ok(())
}


fn download(key: &str, out_path: &path::Path) -> Result<()> {
    println!("Downloading key: {}", key);
    let (access_pass, encrypt_pass_hash, _) = prompt_passwords(false)?;

    let client = reqwest::Client::new()?;

    println!("Fetching metadata...");
    let download_access_params = json!({
        "key": &key,
        "access_password": access_pass.to_hex(),
    }).to_string();
    let url = format!("{}/api/download/init", HOST);
    let mut init_resp = client.post(&url)?
        .header(reqwest::header::ContentType::json())
        .body(download_access_params)
        .send()?;
    let init_resp = unwrap_resp!(init_resp).json::<DownloadInitResp>()?;

    println!("Downloading encrypted bytes...");
    let download_access_params = json!({
        "key": &init_resp.download_key,
        "access_password": access_pass.to_hex(),
    }).to_string();
    let url = format!("{}/api/download", HOST);
    let mut bytes_resp = client.post(&url)?
        .header(reqwest::header::ContentType::json())
        .body(download_access_params)
        .send()?;
    unwrap_resp!(&mut bytes_resp);

    let mut pb = pbr::ProgressBar::new(init_resp.size);
    pb.set_units(pbr::Units::Bytes);
    pb.format("[=> ]");
    let mut enc_bytes = Vec::with_capacity(init_resp.size as usize);
    let mut stream = BufReader::new(bytes_resp);
    loop {
        let n = {
            let buf = stream.fill_buf()?;
            enc_bytes.extend_from_slice(&buf);
            buf.len()
        };
        stream.consume(n);
        if n == 0 { break; }
        pb.add(n as u64);
    }

    let nonce = Vec::from_hex(&init_resp.nonce)?;

    println!("Decrypting data...");
    let bytes = crypto::decrypt(&mut enc_bytes, &nonce, &encrypt_pass_hash)?;
    let hash = crypto::hash(bytes);

    println!("Confirming content hash and fetching file-name...");
    let confirm_params = json!({
        "key": &init_resp.confirm_key,
        "hash": hash.to_hex(),
    }).to_string();
    let url = format!("{}/api/download/confirm", HOST);
    let mut name_resp = client.post(&url)?
        .header(reqwest::header::ContentType::json())
        .body(confirm_params)
        .send()?;
    let name_resp = unwrap_resp!(name_resp).json::<ConfirmResp>()?;

    let mut out_path = if out_path.is_dir() { out_path.join(name_resp.file_name) } else { out_path.to_owned() };
    let exists = out_path.exists();
    println!("Destination file: {:?}", out_path);
    if exists {
        if prompt("Destination file already exists. Overwrite? [y/n] ")? != "y" {
            println!("Looking for an available file-path since the download may no longer be available...");
            let mut n  = 1;
            loop {
                let new_file_name = out_path.file_name()
                    .and_then(std::ffi::OsStr::to_str)
                    .map(|s| s.to_string())
                    .ok_or_else(|| ErrorKind::PathError("malformed filename"))?;
                let new_file_name = format!("{}__{}", new_file_name, n);
                let temp_out_path = out_path
                    .parent()
                    .ok_or_else(|| ErrorKind::PathError("path missing parent"))?
                    .join(new_file_name);
                if ! temp_out_path.exists() {
                    out_path = temp_out_path;
                    break
                }
                n += 1;
            }
        }
    }
    println!("Saving content to: {:?}", out_path);
    let mut file = fs::File::create(out_path)?;
    file.write_all(bytes)?;
    println!("Success!");
    Ok(())
}


fn delete(key: &str) -> Result<()> {
    println!("Deleting key: {}", key);
    let deletion_pass =          rpassword::prompt_password_stdout("Deletion-Password >> ")?;
    let deletion_pass_confirm =  rpassword::prompt_password_stdout("Deletion-Password (confirm) >> ")?;
    if deletion_pass != deletion_pass_confirm { bail!("Deletion passwords do not match!") }
    let deletion_pass_bytes = deletion_pass.as_bytes().to_vec();

    let client = reqwest::Client::new()?;

    let delete_params = json!({
        "key": &key,
        "deletion_password": deletion_pass_bytes.to_hex(),
    }).to_string();
    let url = format!("{}/api/upload/delete", HOST);
    let mut delete_resp = client.post(&url)?
        .header(reqwest::header::ContentType::json())
        .body(delete_params)
        .send()?;
    unwrap_resp!(delete_resp);
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
            let download_limit = match matches.value_of("download_limit") {
                Some(v) => Some(v.parse::<u32>().chain_err(|| "Invalid `download_limit` value")?),
                None => None,
            };
            let lifespan = match matches.value_of("lifespan") {
                Some(v) => Some(v.parse::<u64>().chain_err(|| "Invalid `lifespan` value")?),
                None => None,
            };
            upload(&file_path, download_limit, lifespan)?;
        }
        ("download", Some(matches)) => {
            let key = matches.value_of("key").unwrap();
            let out_path = matches.value_of("out_path").unwrap_or(".");
            let out_path = path::PathBuf::from(out_path);
            download(key, &out_path)?;
        }
        ("delete", Some(matches)) => {
            let key = matches.value_of("key").unwrap();
            delete(key)?;
        }
        _ => println!("no matches!"),
    }
    Ok(())
}


quick_main!(run);

