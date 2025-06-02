#![cfg_attr(
    all(not(debug_assertions), target_os = "windows"),
    windows_subsystem = "windows"
)]
use anyhow::Result;
use dashmap::DashMap;
use druid::commands::CLOSE_ALL_WINDOWS;
use druid::widget::Checkbox;
use druid::widget::{Flex, Label, ProgressBar};
use druid::Color;
use druid::ExtEventSink;
use druid::{
    AppLauncher, Data, FontDescriptor, FontWeight, Lens, Widget, WidgetExt as _, WindowDesc,
};
use flate2::Compression;
use http::Uri;
use semver::Version;
use std::collections::{HashMap, HashSet};
use std::env;
use std::io::{Error, Read, Write};
use std::net::SocketAddr;
use std::path::Path;
use std::process::Command;
use std::ptr::null_mut;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use std::{fs, io};
use winreg::enums::HKEY_CURRENT_USER;
use winreg::RegKey;

use once_cell::sync::Lazy;

use scl_gui_widgets::{
    widget_ext::WidgetExt,
    widgets::{Button, WindowWidget, QUERY_CLOSE_WINDOW},
};

use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use hudsucker::async_trait::async_trait;
use hudsucker::hyper::body::to_bytes;
use hudsucker::hyper::Body;
use hudsucker::rustls::{Certificate, PrivateKey};
use hudsucker::{certificate_authority::RcgenAuthority, hyper::{Request, Response}, HttpContext, HttpHandler, Proxy, RequestOrResponse};
use rcgen::{self, BasicConstraints, Certificate as RCGenCertificate, CertificateParams, DistinguishedName, DnType, IsCa, PKCS_ECDSA_P256_SHA256};
use serde_json::Value;
use time::format_description::well_known::Rfc3339;
use time::{macros::datetime, OffsetDateTime};
use tokio::sync::watch;
use windows_sys::Win32::System::Registry::{KEY_READ, KEY_WRITE};

static URI_CACHE: Lazy<DashMap<SocketAddr, Uri>> = Lazy::new(|| DashMap::new());

static AUTO_FILTER: Lazy<AtomicBool> = Lazy::new(|| AtomicBool::new(false));

#[derive(Clone)]
struct EOSHandler;

#[async_trait]
impl HttpHandler for EOSHandler {
    async fn handle_request(
        &mut self,
        ctx: &HttpContext,
        req: Request<Body>,
    ) -> RequestOrResponse {
        let uri = req.uri().clone();
        URI_CACHE.insert(ctx.client_addr, uri);
        req.into()
    }

    async fn handle_response(
        &mut self,
        ctx: &HttpContext,
        mut res: Response<Body>,
    ) -> Response<Body> {
        use regex::Regex;
        use tokio::task;

        if let Some(uri) = URI_CACHE.get(&ctx.client_addr) {
            let re = Regex::new(r"^/matchmaking/v1/[a-fA-F0-9]{32}/filter$").unwrap();
            if re.is_match(uri.path()) {
                let body_bytes = match to_bytes(res.body_mut()).await {
                    Ok(b) => b,
                    Err(_) => return res,
                };

                let is_gzip = res.headers()
                    .get("content-encoding")
                    .map(|v| v.to_str().unwrap_or("").eq_ignore_ascii_case("gzip"))
                    .unwrap_or(false);

                let filter_set = match load_filter_config() {
                    Ok(cfg) => cfg,
                    Err(_) => return res,
                };


                let json_string = if is_gzip {
                    let mut decoder = GzDecoder::new(&body_bytes[..]);
                    let mut out = String::new();
                    if let Err(_) = decoder.read_to_string(&mut out) {
                        return res;
                    }
                    out
                } else {
                    String::from_utf8_lossy(&body_bytes).to_string()
                };

                let json: Value = match serde_json::from_str(&json_string) {
                    Ok(j) => j,
                    Err(_) => return res,
                };

                let auto_block = AUTO_FILTER.load(Ordering::Relaxed);

                let json = match task::spawn_blocking(move || {
                    let mut json = filter_sessions_by_config(json, &filter_set);
                    if auto_block {
                        json = remove_duplicate_full_sessions(json);
                    }
                    json
                }).await {
                    Ok(processed_json) => processed_json,
                    Err(_) => return res,
                };


                let new_json = match serde_json::to_string(&json) {
                    Ok(j) => j,
                    Err(_) => return res,
                };

                let new_body_bytes = if is_gzip {
                    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
                    if encoder.write_all(new_json.as_bytes()).is_err() {
                        return res;
                    }
                    match encoder.finish() {
                        Ok(b) => b,
                        Err(_) => return res,
                    }
                } else {
                    new_json.into_bytes()
                };

                let mut new_res = Response::builder()
                    .status(res.status())
                    .version(res.version());

                for (key, value) in res.headers() {
                    if key != "content-length" {
                        new_res = new_res.header(key, value.clone());
                    }
                }

                return new_res
                    .header("content-length", new_body_bytes.len().to_string())
                    .body(Body::from(new_body_bytes))
                    .unwrap_or_else(|_| res);
            }
        }

        res
    }
}


#[derive(Debug, Clone, PartialEq)]
pub struct ProxyConfig {
    enable: u32,
    server: Option<String>,
}

#[derive(Debug, Clone, Data, Lens)]
struct AppData {
    progress: f64,
    #[data(eq)]
    ca_installed: bool,
    #[data(eq)]
    is_proxy_enabled: bool,
    #[data(eq)]
    app_version: Version,
    #[data(eq)]
    list_updated_time: Option<OffsetDateTime>,
    #[data(eq)]
    tips_string: String,
    #[data(eq)]
    download_url: Option<String>,
    #[data(eq)]
    auto_block: bool,
    #[data(eq)]
    origin_proxy_config: Option<ProxyConfig>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    let main_window = WindowDesc::new(ui_builder(shutdown_tx))
        .window_size((400., 310.))
        .resizable(false)
        .show_titlebar(false)
        .title("SquadServerBlocker");

    let mut data = AppData {
        progress: 0.,
        ca_installed: false,
        is_proxy_enabled: false,
        app_version: Version::parse(env!("CARGO_PKG_VERSION"))?,
        list_updated_time: None,
        tips_string: String::new(),
        download_url: Some("https://clone.squad.icu/config.json".into()),
        auto_block: false,
        origin_proxy_config: None,
    };
    let launcher = AppLauncher::with_window(main_window);
    
    let key_path = "SquadServerBlocker_CA.key";
    let cer_path = "SquadServerBlocker_CA.cer";
    
    generate_key_and_cer(key_path, cer_path);
    let ca: RcgenAuthority = get_ca(key_path, cer_path)?;
    
    data.ca_installed = is_cert_installed()?;

    data.list_updated_time = get_file_modified_time("config.json");

    start_proxy_server(ca, shutdown_rx);

    launcher
        .configure_env(|env, _| {
            scl_gui_widgets::theme::color::set_color_to_env(
                env,
                scl_gui_widgets::theme::color::Theme::Dark,
            );
        })
        .launch(data)?;
    Ok(())
}

fn ui_builder(shutdown_tx: watch::Sender<bool>) -> impl Widget<AppData> {
    let title = Label::new("SquadServerBlocker".to_string()).with_font(
        FontDescriptor::default()
            .with_size(20.)
            .with_weight(FontWeight::BOLD),
    );

    let app_version = Flex::row()
        .with_child(Label::new("SquadServerBlocker 版本:").with_text_color(Color::grey(0.7)))
        .with_child(
            Label::new(|data: &AppData, _env: &_| -> String { data.app_version.to_string() })
                .with_font(
                    FontDescriptor::default()
                        .with_size(17.)
                        .with_weight(FontWeight::SEMI_BOLD),
                ),
        );

    let is_ca_installed = Flex::row()
        .with_child(Label::new("CA 证书:").with_text_color(Color::grey(0.7)))
        .with_child(
            Label::new(|data: &AppData, _env: &_| -> String {
                match &data.ca_installed {
                    true => "已安装".into(),
                    false => "未安装".into()
                }
            })
                .with_font(
                    FontDescriptor::default()
                        .with_size(17.)
                        .with_weight(FontWeight::SEMI_BOLD),
                ),
        );

    let config_updated_time = Flex::row()
        .with_child(Label::new("配置更新时间:").with_text_color(Color::grey(0.7)))
        .with_child(
            Label::new(|data: &AppData, _env: &_| -> String {
                match &data.list_updated_time {
                    Some(time) => time.format(&Rfc3339).unwrap().into(),
                    None => "未初始化".into(),
                }
            })
                .with_font(
                    FontDescriptor::default()
                        .with_size(17.)
                        .with_weight(FontWeight::SEMI_BOLD),
                ),
        );
    
    let proxy_state = Flex::row()
        .with_child(Label::new("代理状态:").with_text_color(Color::grey(0.7)))
        .with_child(
            Label::new(|data: &AppData, _env: &_| -> String {
                match &data.is_proxy_enabled {
                    true => "已启动".into(),
                    false => "未启动".into()
                }
            })
                .with_font(
                    FontDescriptor::default()
                        .with_size(17.)
                        .with_weight(FontWeight::SEMI_BOLD),
                ),
        );

    let is_auto_block = Checkbox::new("自动检测")
        .on_change(|_ctx, _old, new, _env| {
            AUTO_FILTER.store(*new, Ordering::Relaxed);
        })
        .lens(AppData::auto_block);
    
    let install_ca_button = Button::new("安装证书")
        .disabled_if(|data: &AppData, _env: &_| {
            data.ca_installed
        })
        .on_click(|ctx, data, _env| {
            let event_sink = ctx.get_external_handle();
            let install_result = install_cert();
            if let Ok(install_result) = install_result {
                event_sink.add_idle_callback(move |data: &mut AppData| {
                    data.tips_string = install_result.clone();
                });
            } else {
                event_sink.add_idle_callback(move |data: &mut AppData| {
                    data.tips_string = install_result.unwrap_err().to_string();
                });
            }

            data.ca_installed = is_cert_installed().unwrap();
        });

    let uninstall_ca_button = Button::new("卸载证书")
        .disabled_if(|data: &AppData, _env: &_| {
            !data.ca_installed
        })
        .on_click(|ctx, data, _env| {
            let event_sink = ctx.get_external_handle();
            let uninstall_result = uninstall_cert("Squad Server Blocker CA");
            if let Ok(uninstall_result) = uninstall_result {
                event_sink.add_idle_callback(move |data: &mut AppData| {
                    data.tips_string = uninstall_result.clone();
                });
            } else {
                event_sink.add_idle_callback(move |data: &mut AppData| {
                    data.tips_string = uninstall_result.unwrap_err().to_string();
                });
            }

            data.ca_installed = is_cert_installed().unwrap();
        });

    let update_list_button = Button::new("更新配置")
        .on_click(|ctx, data: &mut AppData, _env| {
            let event_sink = ctx.get_external_handle();
            let url: String = data.download_url.as_ref().unwrap().clone();

            let _ = fs::remove_file("config.json");

            tokio::spawn(async move {
                download_file(&url, "config.json", event_sink.clone());
                tokio::time::sleep(Duration::from_millis(300)).await;

                event_sink.add_idle_callback(move |data: &mut AppData| {
                    data.list_updated_time = get_file_modified_time("config.json");
                    data.tips_string = "配置更新完成".into();
                });
            });
        });

    let start_proxy_button = Button::new("启动代理")
        .disabled_if(|data: &AppData, _env: &_| {
            data.is_proxy_enabled ||
                !data.ca_installed
        })
        .on_click(|ctx, _data, _env| {
            let event_sink = ctx.get_external_handle();
            let origin_proxy_config = set_local_proxy().unwrap();

            event_sink.add_idle_callback(move |data: &mut AppData| {
                data.tips_string = "代理设置成功".into();
                data.is_proxy_enabled = true;
                data.origin_proxy_config = Some(origin_proxy_config);
            });
        });

    let stop_proxy_button = Button::new("停止代理")
        .disabled_if(|data: &AppData, _env: &_| {
            !data.is_proxy_enabled ||
                !data.ca_installed
        })
        .on_click(|ctx, data, _env| {
            let event_sink = ctx.get_external_handle();
            restore_proxy(data.origin_proxy_config.clone()).expect("Proxy restore failed");
            event_sink.add_idle_callback(move |data: &mut AppData| {
                data.tips_string = "代理还原成功".into();
                data.is_proxy_enabled = false;
                data.origin_proxy_config = None;
            });
        });
    
    let tips = Label::new(|data: &AppData, _env: &_| -> String {
        data.tips_string.clone()
    });

    let progress_bar = ProgressBar::new().lens(AppData::progress).expand_width();

    WindowWidget::new(
        "SquadServerBlocker",
        Flex::column()
            .with_child(title)
            .with_child(app_version)
            .with_child(is_ca_installed)
            .with_child(config_updated_time)
            .with_child(proxy_state)
            .with_spacer(5.)
            .with_child(tips)
            .with_child(is_auto_block)
            .with_spacer(5.)
            .with_child(
                Flex::row()
                    .with_flex_child(install_ca_button.expand_width(), 1.)
                    .with_spacer(5.)
                    .with_flex_child(uninstall_ca_button.expand_width(), 1.)
                    .with_spacer(5.)
                    .with_flex_child(update_list_button.expand_width(), 1.)
            )
            .with_spacer(5.)
            .with_child(
                Flex::row()
                    .with_flex_child(start_proxy_button.expand_width(), 1.)
                    .with_spacer(5.)
                    .with_flex_child(stop_proxy_button.expand_width(), 1.)
            )
            .with_spacer(5.)
            .with_child(progress_bar)
            .cross_axis_alignment(druid::widget::CrossAxisAlignment::Start)
            .padding(10.),
    )
    .on_notify(QUERY_CLOSE_WINDOW, move |ctx, _, _| {
        let _ = shutdown_tx.send(true);
        restore_proxy(None).expect("Restore proxy failed at exit.");
        ctx.submit_command(CLOSE_ALL_WINDOWS);
    })
}

fn generate_key_and_cer(key_path: &str, cer_path: &str) {
    if Path::new(key_path).exists() && Path::new(cer_path).exists() {
        return;
    }

    let mut cert_params = CertificateParams::default();

    cert_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    cert_params.not_before = OffsetDateTime::from(datetime!(1970-01-01 0:00 UTC));
    cert_params.not_after = OffsetDateTime::from(datetime!(5000-01-01 0:00 UTC));
    cert_params.key_pair = None;
    cert_params.alg = &PKCS_ECDSA_P256_SHA256;

    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "Squad Server Blocker CA");
    dn.push(DnType::OrganizationName, "RingLo_");
    dn.push(DnType::CountryName, "CN");
    
    cert_params.distinguished_name = dn;

    let new_cert = RCGenCertificate::from_params(cert_params).unwrap();
    fs::write(cer_path, new_cert.serialize_pem().unwrap()).unwrap();
    fs::write(key_path, new_cert.serialize_private_key_pem()).unwrap();
}

fn get_ca(key_path: &str, cer_path: &str) -> Result<RcgenAuthority, Error> {
    use std::io::Read;

    let mut key_buffer: Vec<u8> = Vec::new();
    let f = fs::File::open(key_path);
    match f {
        Ok(mut file) => {
            let res = file.read_to_end(&mut key_buffer);
            if let Err(e) = res {
                return Err(e)
            }
        },
        Err(e) => return Err(e)
    }

    let mut cer_buffer: Vec<u8> = Vec::new();
    let f = fs::File::open(cer_path);
    match f {
        Ok(mut file) => {
            let res = file.read_to_end(&mut cer_buffer);
            if let Err(e) = res {
                return Err(e)
            }
        },
        Err(e) => return Err(e)
    }

    {
        let mut key_buffer_ref = key_buffer.as_slice();
        let mut cert_buffer_ref = cer_buffer.as_slice();

        let mut private_key_raw = rustls_pemfile::pkcs8_private_keys(&mut key_buffer_ref).unwrap();
        let mut ca_cert_raw = rustls_pemfile::certs(&mut cert_buffer_ref).unwrap();

        let private_key = PrivateKey(private_key_raw.remove(0));
        let ca_cert = Certificate(ca_cert_raw.remove(0));

        Ok(RcgenAuthority::new(private_key, ca_cert, 1000).unwrap())
    }
}

fn is_cert_installed() -> io::Result<bool> {
    let output = Command::new("certutil")
        .args(&["-store", "Root"])
        .output()?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    Ok(stdout.contains("Squad Server Blocker CA"))
}

fn install_cert() -> io::Result<String> {
    if !Path::new("SquadServerBlocker_CA.cer").exists() {
        return Err(Error::new(io::ErrorKind::NotFound, "证书文件不存在"));
    }

    let output = Command::new("certutil")
        .args(&["-addstore", "Root", "SquadServerBlocker_CA.cer"])
        .output()?;

    if output.status.success() {
        Ok("证书已成功安装到受信任根存储区".to_string())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Ok(format!("安装失败：{}", stderr.trim()))
    }
}

fn uninstall_cert(cert_name: &str) -> io::Result<String> {
    let output = Command::new("certutil")
        .args(&["-delstore", "Root", cert_name])
        .output()?;

    if output.status.success() {
        Ok(format!("已成功从根证书存储区卸载：{}", cert_name))
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Ok(format!("卸载失败：{}", stderr.trim()))
    }
}

fn get_file_modified_time(path: &str) -> Option<OffsetDateTime> {
    let metadata = fs::metadata(Path::new(path)).ok()?;
    let modified = metadata.modified().ok()?;
    OffsetDateTime::from(modified).into()
}

fn download_file(url: &str, path: &str, event_sink: ExtEventSink) {
    let tip_str = format!("正在下载: {path}");
    event_sink.add_idle_callback(move |data: &mut AppData| {
        data.tips_string = tip_str;
    });
    use std::fs::File;
    use std::io::Write;

    let res = tinyget::get(url)
        .with_header(
            "User-Agent",
            &format!("SquadServerBlocker/{};", env!("CARGO_PKG_VERSION")),
        )
        .send_lazy()
        .unwrap();

    let file_size = res
        .headers
        .get("content-length")
        .map(|x| x.as_str().parse::<usize>())
        .unwrap_or(Ok(0))
        .unwrap_or(0);

    event_sink.add_idle_callback(move |data: &mut AppData| {
        data.tips_string = "正在下载…".into();
    });

    let mut file = File::create(path)
        .or(Err(format!("Failed to create file '{path}'")))
        .unwrap();

    let mut buf = Vec::with_capacity(file_size);
    let mut tip_str = "正在下载…".to_string();
    for data in res {
        let (byte, length) = data.unwrap();
        buf.reserve(length);
        buf.push(byte);

        let progress = buf.len() as f64 / file_size as f64;
        let percent_progress = ((progress * 100.).floor() as u32).min(100).max(0);
        let new_tip_str = format!("正在下载：{path}（{percent_progress}%）");
        if tip_str != new_tip_str {
            tip_str = new_tip_str.to_owned();
            event_sink.add_idle_callback(move |data: &mut AppData| {
                data.tips_string = new_tip_str;
                data.progress = progress;
            });
        }
    }

    file.write_all(&buf).unwrap();

    event_sink.add_idle_callback(move |data: &mut AppData| {
        data.tips_string = "".to_string();
    });
}

fn start_proxy_server(ca: RcgenAuthority, shutdown_rx: watch::Receiver<bool>){
    let proxy = Proxy::builder()
        .with_addr(SocketAddr::from(([127, 0, 0, 1], 6776)))
        .with_rustls_client()
        .with_ca(ca)
        .with_http_handler(EOSHandler)
        .build();

    tokio::spawn(async move {
        proxy.start(async {
            shutdown_rx.clone().changed().await.unwrap();
        })
            .await
            .unwrap();
    });
}

fn set_local_proxy() -> io::Result<ProxyConfig> {
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let internet_settings = hkcu.open_subkey_with_flags(r"Software\Microsoft\Windows\CurrentVersion\Internet Settings", KEY_READ | KEY_WRITE)?;

    let proxy_enable: u32 = internet_settings.get_value("ProxyEnable").unwrap_or(0);
    let proxy_server: Option<String> = internet_settings.get_value("ProxyServer").ok();

    let original_config = ProxyConfig {
        enable: proxy_enable,
        server: proxy_server,
    };

    internet_settings.set_value("ProxyEnable", &1u32)?;
    internet_settings.set_value("ProxyServer", &"127.0.0.1:6776")?;

    refresh_proxy_settings()?;

    Ok(original_config)
}

fn restore_proxy(config: Option<ProxyConfig>) -> io::Result<()> {
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let internet_settings = hkcu.open_subkey_with_flags(r"Software\Microsoft\Windows\CurrentVersion\Internet Settings", KEY_WRITE)?;

    if let Some(config) = config {
        internet_settings.set_value("ProxyEnable", &config.enable)?;
        if let Some(server) = config.server {
            internet_settings.set_value("ProxyServer", &server)?;
        } else {
            let _ = internet_settings.delete_value("ProxyServer");
        }
    }
    else {
        internet_settings.set_value("ProxyEnable", &0u32)?;
    }

    refresh_proxy_settings()
}

fn refresh_proxy_settings() -> io::Result<()> {
    use windows_sys::Win32::Networking::WinInet::{
        InternetSetOptionW, INTERNET_OPTION_REFRESH, INTERNET_OPTION_SETTINGS_CHANGED,
    };

    unsafe {
        if InternetSetOptionW(null_mut(), INTERNET_OPTION_SETTINGS_CHANGED, null_mut(), 0) == 0 {
            return Err(Error::last_os_error());
        }
        if InternetSetOptionW(null_mut(), INTERNET_OPTION_REFRESH, null_mut(), 0) == 0 {
            return Err(Error::last_os_error());
        }
    }

    Ok(())
}

fn load_filter_config() -> Result<HashSet<String>> {
    let path = "config.json";

    let content = fs::read_to_string(path)?;
    let config: Value = serde_json::from_str(&content)?;

    let filter_set: HashSet<String> = config
        .get("FilterOutAddresses")
        .and_then(|f| f.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();

    Ok(filter_set)
}

fn filter_sessions_by_config(mut json: Value, filter_set: &HashSet<String>) -> Value {
    if let Some(sessions) = json.get_mut("sessions").and_then(|v| v.as_array_mut()) {
        sessions.retain(|session| {
            let ip = session["attributes"]["ADDRESS_s"].as_str().unwrap_or_default();
            let addr_bound = session["attributes"]["ADDRESSBOUND_s"].as_str().unwrap_or_default();
            let port = addr_bound.split(':').nth(1).unwrap_or_default();
            let full = format!("{}:{}", ip, port);
            !filter_set.contains(&full)
        });
    }
    json
}

fn remove_duplicate_full_sessions(mut json: Value) -> Value {
    if let Some(sessions) = json.get_mut("sessions").and_then(|v| v.as_array_mut()) {
        let mut counts: HashMap<String, usize> = HashMap::new();
        for session in sessions.iter() {
            let ip = session["attributes"]["ADDRESS_s"].as_str().unwrap_or_default();
            let addr_bound = session["attributes"]["ADDRESSBOUND_s"].as_str().unwrap_or_default();
            let port = addr_bound.split(':').nth(1).unwrap_or_default();
            let full = format!("{}:{}", ip, port);
            *counts.entry(full).or_insert(0) += 1;
        }

        sessions.retain(|session| {
            let ip = session["attributes"]["ADDRESS_s"].as_str().unwrap_or_default();
            let addr_bound = session["attributes"]["ADDRESSBOUND_s"].as_str().unwrap_or_default();
            let port = addr_bound.split(':').nth(1).unwrap_or_default();
            let full = format!("{}:{}", ip, port);
            counts.get(&full).copied().unwrap_or(0) == 1
        });
    }
    json
}
