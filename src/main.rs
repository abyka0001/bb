use anyhow::Result;
use aes::cipher::{BlockEncrypt, KeyInit, generic_array::GenericArray};
use aes::Aes128;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use futures::future::join_all;
use rand::seq::SliceRandom;
use reqwest::header::{HeaderMap, CONTENT_TYPE, USER_AGENT, ACCEPT_ENCODING, CONNECTION};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::fs;
use twilight_gateway::{Intents, Shard, ShardId};
use twilight_model::gateway::event::Event;
use uuid::Uuid;

const GUILD_ID: u64 = 1394703406064734378;
const CHANNEL_ID: u64 = 1470118920890487028;
const API_SECRET: &str = "9EuDKGtoWAOWoQH1cRng-d5ihNN60hkGLaRiaZTk-6s";
const API_KEY_X: &str = "6aDtpIdzQdgGwrpP6HzuPA";
const BOT_TOKEN: &str = "MTQ2MTM3MzYwNDUxNTI4NzIzNw.GJdm5s.Ike9lvZ0Rn5NKggQ8QnKO88Hs0-GSe6A16ZHVI";

#[derive(Debug, Clone)]
struct Account {
    id: String,
    token: String,
    register_ts: String,
    device_register_ts: String,
    device_id: String,
}

impl Account {
    fn from_line(line: &str) -> Option<Self> {
        let parts: Vec<&str> = line.trim().split(',').collect();
        if parts.len() < 5 { return None; }
        Some(Self {
            id: parts[0].to_string(),
            token: parts[1].to_string(),
            register_ts: parts[2].to_string(),
            device_register_ts: parts[3].to_string(),
            device_id: parts[4].to_string(),
        })
    }
}

struct State {
    http: reqwest::Client,
    accounts: Vec<Account>,
    discord_http: twilight_http::Client,
}

fn enc_token(token: &str, nonce: &str) -> String {
    let combined = format!("{}{}", token, nonce);
    let key_hex = format!("{:x}", md5::compute(API_SECRET.as_bytes()));
    let key = &key_hex.as_bytes()[..16];

    let xored: Vec<u8> = combined.bytes().map(|b| b ^ 0x73).collect();

    let block_size = 16;
    let len = xored.len();
    let padding_len = block_size - (len % block_size);
    let padded_len = len + padding_len;
    
    let mut buffer = vec![0u8; padded_len];
    buffer[..len].copy_from_slice(&xored);
    for i in len..padded_len {
        buffer[i] = padding_len as u8;
    }

    let cipher = Aes128::new(GenericArray::from_slice(key));
    
    for chunk in buffer.chunks_mut(block_size) {
        let block = GenericArray::from_mut_slice(chunk);
        cipher.encrypt_block(block);
    }

    BASE64.encode(buffer)
}

fn generate_sign(path: &str, nonce: &str, time: &str, data: &str, device_id: &str) -> String {
    let raw = format!("{}{}{}{}{}{}", API_KEY_X, path, nonce, time, data, API_SECRET);
    let first_md5 = format!("{:x}", md5::compute(raw));
    let final_raw = format!("{}{}", first_md5, device_id);
    format!("{:x}", md5::compute(final_raw))
}

async fn send_request(
    client: &reqwest::Client, 
    account: &Account, 
    target_id: &str, 
    is_settings: bool
) -> Result<bool> {
    let nonce = Uuid::new_v4().to_string();
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs().to_string();
    
    let (url_path, data) = if is_settings {
        ("/friend/api/v1/friends/settings", format!("{{\"addFriendMarker\":1,\"userId\":{}}}", target_id))
    } else {
        ("/friend/api/v1/friends", format!("{{\"channel\":1,\"friendId\":{},\"gameId\":\"\",\"msg\":\"Let's be friends!\",\"type\":1}}", target_id))
    };

    let x_sign = generate_sign(url_path, &nonce, &now, &data, &account.device_id);
    let host = if rand::random::<bool>() { "gw" } else { "gwbyte" };
    let url = format!("http://{}.sandboxol.com{}", host, url_path);

    let mut headers = HeaderMap::new();
    headers.insert("userId", account.id.parse()?);
    headers.insert("packageName", "blockymods".parse()?);
    headers.insert("packageNameFull", "com.sandboxol.blockymods".parse()?);
    headers.insert("androidVersion", "36".parse()?);
    headers.insert("OS", "android".parse()?);
    headers.insert("appType", "android".parse()?);
    headers.insert("appLanguage", "en".parse()?);
    headers.insert("appVersion", "5542".parse()?);
    headers.insert("appVersionName", "3.8.2".parse()?);
    headers.insert("channel", "sandbox".parse()?);
    headers.insert("uid_register_ts", account.register_ts.parse()?);
    headers.insert("device_register_ts", account.device_register_ts.parse()?);
    headers.insert("eventType", "app".parse()?);
    headers.insert("userDeviceId", account.device_id.parse()?);
    headers.insert("userLanguage", "en_US".parse()?);
    headers.insert("region", "RU".parse()?);
    headers.insert("clientType", "client".parse()?);
    headers.insert("env", "prd".parse()?);
    headers.insert("package_name_en", "com.sandboxol.blockymods".parse()?);
    headers.insert("md5", "5d0de77b0f4b93b44669f146e54b49d9".parse()?);
    headers.insert("X-ApiKey", API_KEY_X.parse()?);
    headers.insert("X-Nonce", nonce.parse()?);
    headers.insert("X-Time", now.parse()?);
    headers.insert("X-Sign", x_sign.parse()?);
    headers.insert("X-UrlPath", url_path.parse()?);
    headers.insert("Access-Token", enc_token(&account.token, &nonce).parse()?);
    headers.insert(CONTENT_TYPE, "application/json; charset=UTF-8".parse()?);
    headers.insert(CONNECTION, "Keep-Alive".parse()?);
    headers.insert(ACCEPT_ENCODING, "gzip".parse()?);
    headers.insert(USER_AGENT, "okhttp/4.12.0".parse()?);

    let res = client.post(url).headers(headers).body(data).send().await?;
    if res.status().is_success() {
        let text = res.text().await?;
        return Ok(text.contains("SUCCESS"));
    }
    Ok(false)
}

#[tokio::main]
async fn main() -> Result<()> {
    let content = fs::read_to_string("noban.txt").await.expect("Could not read noban.txt");
    let accounts: Vec<Account> = content.lines().filter_map(Account::from_line).collect();
    println!("Loaded {} accounts", accounts.len());

    let http_client = reqwest::Client::builder()
        .pool_max_idle_per_host(200)
        .tcp_keepalive(std::time::Duration::from_secs(60))
        .build()?;

    let intents = Intents::GUILD_MESSAGES | Intents::MESSAGE_CONTENT;
    let mut shard = Shard::new(ShardId::ONE, BOT_TOKEN.to_string(), intents);
    let discord_http = twilight_http::Client::new(BOT_TOKEN.to_string());

    let state = Arc::new(State {
        http: http_client,
        accounts,
        discord_http,
    });

    println!("Bot is running...");

    loop {
        let event = match shard.next_event().await {
            Ok(event) => event,
            Err(source) => {
                if source.is_fatal() { break; }
                continue;
            }
        };

        let state_clone = state.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_event(event, state_clone).await {
                eprintln!("Handler error: {:?}", e);
            }
        });
    }
    Ok(())
}

async fn handle_event(event: Event, state: Arc<State>) -> Result<()> {
    if let Event::MessageCreate(msg) = event {
        if msg.author.bot || msg.guild_id.map(|id| id.get()) != Some(GUILD_ID) || msg.channel_id.get() != CHANNEL_ID {
            return Ok(());
        }

        if msg.content.starts_with(".f ") {
            let parts: Vec<&str> = msg.content.split_whitespace().collect();
            let target_id = match parts.get(1) {
                Some(id) if id.chars().all(char::is_numeric) => *id,
                _ => {
                    state.discord_http.delete_message(msg.channel_id, msg.id).await?;
                    return Ok(());
                }
            };

            // Выбираем аккаунты заранее, чтобы не держать ThreadRng через await
            let settings_account = {
                let mut rng = rand::thread_rng();
                state.accounts.choose(&mut rng).cloned()
            };

            if let Some(acc) = settings_account {
                let _ = send_request(&state.http, &acc, target_id, true).await;
            }

            let mut tasks = Vec::with_capacity(100);
            {
                let mut rng = rand::thread_rng();
                for _ in 0..100 {
                    if let Some(acc) = state.accounts.choose(&mut rng) {
                        let client = state.http.clone();
                        let acc_clone = acc.clone();
                        let tid = target_id.to_string();
                        tasks.push(tokio::spawn(async move {
                            send_request(&client, &acc_clone, &tid, false).await
                        }));
                    }
                }
            } // rng удаляется здесь

            let results = join_all(tasks).await;
            let success_count = results.into_iter()
                .filter_map(|r| r.ok()) // JoinHandle result
                .filter_map(|r| r.ok()) // send_request result
                .filter(|&success| success)
                .count();

            let response = format!(
                "{} friend requests were sent to player {}\n\nAutomatically “Allow anyone to send friend requests”.", 
                success_count, target_id
            );

            state.discord_http.create_message(msg.channel_id)
                .content(&response)?
                .reply(msg.id)
                .await?;
        }
    }
    Ok(())
  }
