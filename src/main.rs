use dotenvy::dotenv;
use ethers::prelude::*;
use ethers::providers::{Provider, Http};
use ethers::core::k256::ecdsa::SigningKey;
use std::str::FromStr;
use std::sync::Arc;
use tokio::time::{sleep, Duration};
use rand::Rng;
use reqwest::{Client, StatusCode};
use serde::{Deserialize, Serialize};
use url::Url;

// Contract Address & ABI
const FUN_CONTRACT_ADDRESS: &str = "0x16f2fec3bf691e1516b186f51e0daa5114c9b5e8";
const FUN_ABI: &str = r#"[
  "function addFun(string message) payable",
  "function paused() view returns (bool)",
  "function funFee() view returns (uint256)"
]"#;
const NETWORK_NAME: &str = "Somnia Testnet";
const FUN_FEE_ETHER: f64 = 0.1;

// Messages
const FUN_MESSAGES: [&str; 10] = [
  "hallo",
  "gm",
  "Have a great day!",
  "Sending some fun your way!",
  "Keep smiling!",
  "You're awesome!",
  "Stay positive!",
  "Make today amazing!",
  "Believe in yourself!",
  "You got this!"
];

#[derive(Serialize)]
struct WalletAuthPayload {
    address: String,
    signature: String,
    message: String,
}

#[derive(Deserialize)]
struct LoginResponse {
    success: bool,
    message: Option<String>,
}

#[derive(Serialize)]
struct MintNftPayload {
    walletAddress: String,
    message: String,
}

#[derive(Deserialize)]
struct MintNftResponse {
    success: bool,
    message: Option<String>,
}

struct WalletInfo {
    address: String,
    balance: String,
    network: String,
}

fn get_random_delay() -> u64 {
    let mut rng = rand::thread_rng();
    rng.gen_range(30..60) // 30 to 60 seconds
}

async fn get_wallet_info(wallet: &LocalWallet<SigningKey>, provider: &Arc<Provider<Http>>) -> Result<WalletInfo, Box<dyn std::error::Error>> {
    let address = format!("{:?}", wallet.address());
    let stt_balance = provider.get_balance(wallet.address(), None).await?;
    let balance_stt = ethers::utils::format_ether(stt_balance);

    Ok(WalletInfo {
        address,
        balance: balance_stt,
        network: NETWORK_NAME.to_string(),
    })
}

async fn login_wallet(client: &Client, wallet: &LocalWallet<SigningKey>) -> Result<String, Box<dyn std::error::Error>> {
    println!("Melakukan login wallet untuk akun {}", wallet.address());
    let nonce = chrono::Utc::now().timestamp_millis().to_string();
    let message = format!("I accept the Quills Adventure Terms of Service at https://quills.fun/terms\n\nNonce: {}", nonce);
    let signature = wallet.sign_message(&message).await?;

    let payload = WalletAuthPayload {
        address: format!("{:?}", wallet.address()),
        signature: format!("0x{}", hex::encode(signature.to_vec())),
        message,
    };

    let response = client.post("https://quills.fun/api/auth/wallet")
        .json(&payload)
        .send()
        .await?;

    if response.status() == StatusCode::OK {
        let login_res: LoginResponse = response.json().await?;
        if login_res.success {
            let auth_token = response.cookies().find(|c| c.name() == "auth_token")
                .ok_or("Auth token not found in cookies")?
                .value()
                .to_string();
            println!("Login wallet berhasil untuk akun {}", wallet.address());
            Ok(auth_token)
        } else {
            Err(format!("Login wallet gagal: {}", login_res.message.unwrap_or_default()).into())
        }
    } else {
        Err(format!("Login wallet gagal dengan status code: {}", response.status()).into())
    }
}

async fn mint_nft(client: &Client, auth_token: &str, wallet_address: &str, message: &str) -> Result<(), Box<dyn std::error::Error>> {
    let payload = MintNftPayload {
        walletAddress: wallet_address.to_string(),
        message: message.to_string(),
    };

    let response = client.post("https://quills.fun/api/mint-nft")
        .header("Cookie", format!("auth_token={}", auth_token))
        .json(&payload)
        .send()
        .await?;

    if response.status() == StatusCode::OK {
        let mint_res: MintNftResponse = response.json().await?;
        if mint_res.success {
            println!("Mint NFT berhasil untuk pesan: \"{}\"", message);
            Ok(())
        } else {
            Err(format!("Mint NFT gagal: {}", mint_res.message.unwrap_or_default()).into())
        }
    } else {
        Err(format!("Mint NFT gagal dengan status code: {}", response.status()).into())
    }
}

async fn auto_send_fun(
    client: &Client,
    wallet: &LocalWallet<SigningKey>,
    provider: &Arc<Provider<Http>>,
    auth_token: &str
) -> Result<(), Box<dyn std::error::Error>> {
    let contract_address = Address::from_str(FUN_CONTRACT_ADDRESS)?;
    let contract = Contract::new(contract_address, FunAbi::abi(), Arc::new(wallet.clone()));

    let is_paused: bool = contract.method("paused", ())?.call().await?;
    if is_paused {
        return Err("Kontrak Quill Fun sedang dalam status paused.".into());
    }

    let contract_fun_fee: U256 = contract.method("funFee", ())?.call().await?;
    let contract_fun_fee_ether = ethers::utils::format_ether(contract_fun_fee).parse::<f64>()?;
    let stt_amount = FUN_FEE_ETHER;

    if contract_fun_fee_ether > stt_amount {
        return Err(format!("Biaya kontrak {} STT lebih tinggi dari FUN_FEE {} STT.", contract_fun_fee_ether, stt_amount).into());
    }

    let wallet_info = get_wallet_info(wallet, provider).await?;
    let stt_balance = wallet_info.balance.parse::<f64>()?;
    if stt_balance < stt_amount {
        return Err(format!("Saldo STT tidak cukup: {} < {}", stt_balance, stt_amount).into());
    }

    let message = FUN_MESSAGES[rand::thread_rng().gen_range(0..FUN_MESSAGES.len())];
    println!("Melakukan send fun: \"{}\" dengan {} STT", message, stt_amount);

    let amount_in_wei = ethers::utils::parse_ether(stt_amount)?;
    
    let tx = contract.method::<_, H256>("addFun", (message.to_string(),))?.value(amount_in_wei).send().await?.await?;

    if let Some(receipt) = tx {
        if let Some(status) = receipt.status {
            if status == U64::from(1) {
                println!("Send Fun Berhasil. Hash: {:?}", receipt.transaction_hash);
                mint_nft(client, auth_token, &wallet_info.address, message).await?;
                return Ok(());
            }
        }
    }

    Err("Send Fun Gagal: Transaksi reverted.".into())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenv().ok();
    env_logger::init();

    let private_keys_str = std::env::var("PRIVATE_KEYS").expect("PRIVATE_KEYS must be set");
    let rpc_url = std::env::var("RPC_URL_SOMNIA_TESTNET").expect("RPC_URL_SOMNIA_TESTNET must be set");
    let private_keys: Vec<&str> = private_keys_str.split(',').collect();
    
    let http_provider = Provider::<Http>::try_from(rpc_url)?;
    let provider = Arc::new(http_provider);
    let client = reqwest::Client::new();
    
    println!("Masukkan jumlah kali auto send fun per akun:");
    let mut loop_count_str = String::new();
    std::io::stdin().read_line(&mut loop_count_str)?;
    let loop_count: u32 = loop_count_str.trim().parse()?;

    for (i, pk) in private_keys.iter().enumerate() {
        println!("\n=============================================");
        println!("Memulai bot untuk akun ke-{}...", i + 1);

        let wallet = pk.trim().parse::<LocalWallet<SigningKey>>()?;
        let wallet = wallet.with_chain_id(999999);
        let wallet = wallet.connect(provider.clone());

        let wallet_info = get_wallet_info(&wallet, &provider).await?;
        println!("Informasi Wallet: \n  Alamat: {}\n  Saldo: {} STT\n  Jaringan: {}",
            wallet_info.address, wallet_info.balance, wallet_info.network
        );

        let auth_token = match login_wallet(&client, &wallet).await {
            Ok(token) => token,
            Err(e) => {
                println!("Gagal login untuk akun {}: {}", wallet_info.address, e);
                continue;
            }
        };

        for j in 1..=loop_count {
            println!("Memulai send fun ke-{} untuk akun {}", j, i + 1);
            if let Err(e) = auto_send_fun(&client, &wallet, &provider, &auth_token).await {
                println!("Transaksi gagal: {}", e);
            }
            
            if j < loop_count {
                let delay = get_random_delay();
                println!("Send fun ke-{} selesai. Menunggu {} detik...", j, delay);
                sleep(Duration::from_secs(delay)).await;
            }
        }
    }

    println!("Semua akun telah selesai.");
    Ok(())
}

abigen!(
    FunAbi,
    r#"[
        "function addFun(string message) payable",
        "function paused() view returns (bool)",
        "function funFee() view returns (uint256)"
    ]"#,
    event_derives(serde::Deserialize, serde::Serialize)
);
