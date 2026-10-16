#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use eframe::egui;
use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;

#[cfg(target_os = "windows")]
use std::os::windows::process::CommandExt;

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([600.0, 700.0])
            .with_min_inner_size([520.0, 560.0])
            .with_title("MSN-GUARD Windows 桌面端"),
        ..Default::default()
    };

    eframe::run_native(
        "MSN-GUARD",
        options,
        Box::new(|cc| {
            setup_custom_fonts(&cc.egui_ctx);
            Ok(Box::new(MsnGuardApp::default()))
        }),
    )
}

// 加载 Windows 微软雅黑字体以正常显示中文
fn setup_custom_fonts(ctx: &egui::Context) {
    let mut fonts = egui::FontDefinitions::default();
    if let Ok(font_data) = std::fs::read("C:\\Windows\\Fonts\\msyh.ttc") {
        fonts.font_data.insert(
            "msyh".to_owned(),
            egui::FontData::from_owned(font_data),
        );
        fonts
            .families
            .entry(egui::FontFamily::Proportional)
            .or_default()
            .insert(0, "msyh".to_owned());
        fonts
            .families
            .entry(egui::FontFamily::Monospace)
            .or_default()
            .push("msyh".to_owned());
        ctx.set_fonts(fonts);
    }
}

struct MsnGuardApp {
    // 核心协议与传输配置
    protocol: String,
    masque_carrier: String,
    scan_mode: String,
    noize_profile: String,
    ip_version: String,

    // SHARD 专属配置项
    enable_shard: bool,
    shard_size: String,
    shard_sleep_ms: String,
    shard_mode: String,
    ech_mode: String,
    custom_sni: String,

    // 节点与端口配置
    custom_peer: String,
    custom_inner_peer: String,
    socks_listen: String,
    http_listen: String,

    // 链式传输与附加功能
    chain_mode: String,
    bypass_lan_iran: bool,
    sys_proxy: bool,

    // 运行状态与进程管理
    is_running: bool,
    child_proc: Arc<Mutex<Option<Child>>>,
    logs: Arc<Mutex<Vec<String>>>,
}

impl Default for MsnGuardApp {
    fn default() -> Self {
        Self {
            protocol: "shard".to_string(),
            masque_carrier: "h3".to_string(),
            scan_mode: "verified".to_string(),
            noize_profile: "firewall".to_string(),
            ip_version: "4".to_string(),

            enable_shard: true,
            shard_size: "24".to_string(),
            shard_sleep_ms: "10".to_string(),
            shard_mode: "tls".to_string(),
            ech_mode: "off".to_string(),
            custom_sni: String::new(),

            custom_peer: String::new(),
            custom_inner_peer: String::new(),
            socks_listen: "127.0.0.1:1819".to_string(),
            http_listen: "127.0.0.1:1820".to_string(),

            chain_mode: "none".to_string(),
            bypass_lan_iran: false,
            sys_proxy: true,

            is_running: false,
            child_proc: Arc::new(Mutex::new(None)),
            logs: Arc::new(Mutex::new(vec![
                "[*] 欢迎使用 MSN-GUARD Windows 客户端 (含 SHARD 抗审查引擎)".to_string(),
                "[*] 请确保 aether.exe 与本程序在同一文件夹下".to_string(),
            ])),
        }
    }
}

impl MsnGuardApp {
    fn append_log(&self, msg: impl Into<String>) {
        if let Ok(mut logs) = self.logs.lock() {
            logs.push(msg.into());
            if logs.len() > 600 {
                logs.remove(0);
            }
        }
    }

    fn set_windows_system_proxy(&self, enable: bool) {
        #[cfg(target_os = "windows")]
        {
            const CREATE_NO_WINDOW: u32 = 0x08000000;
            let reg_path = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings";
            if enable {
                let proxy_server = if !self.http_listen.trim().is_empty() {
                    self.http_listen.trim().to_string()
                } else {
                    format!("socks={}", self.socks_listen.trim())
                };
                let _ = Command::new("reg")
                    .args(["add", reg_path, "/v", "ProxyEnable", "/t", "REG_DWORD", "/d", "1", "/f"])
                    .creation_flags(CREATE_NO_WINDOW)
                    .status();
                let _ = Command::new("reg")
                    .args(["add", reg_path, "/v", "ProxyServer", "/t", "REG_SZ", "/d", &proxy_server, "/f"])
                    .creation_flags(CREATE_NO_WINDOW)
                    .status();
                self.append_log(format!("[+] 已开启 Windows 系统代理: {}", proxy_server));
            } else {
                let _ = Command::new("reg")
                    .args(["add", reg_path, "/v", "ProxyEnable", "/t", "REG_DWORD", "/d", "0", "/f"])
                    .creation_flags(CREATE_NO_WINDOW)
                    .status();
                self.append_log("[*] 已关闭 Windows 系统代理");
            }
        }
    }

    fn start_core(&mut self, ctx: egui::Context) {
        let mut cmd = Command::new("./aether.exe");

        // 1. 解析主协议与独立传输通道
        match self.protocol.as_str() {
            "shard" => {
                // SHARD 协议底层采用 TCP/H2 + TLS 分片穿透
                cmd.env("AETHER_PROTOCOL", "masque");
                cmd.env("AETHER_MASQUE_HTTP2", "1");
                cmd.env("AETHER_SHARD", "1");
                cmd.env("AETHER_FRAGMENT", "1");
            }
            "psiphon_only" => {
                cmd.env("AETHER_PSIPHON", "only");
                cmd.env("AETHER_PROTOCOL", "masque");
            }
            "tor_only" => {
                cmd.env("AETHER_TOR", "only");
                cmd.env("AETHER_PROTOCOL", "masque");
            }
            other => {
                cmd.env("AETHER_PROTOCOL", other);
                if (other == "masque" || other == "mim") && self.masque_carrier == "h2" {
                    cmd.env("AETHER_MASQUE_HTTP2", "1");
                }
            }
        }

        // 2. 注入 SHARD 分片参数（当选择 SHARD 协议或手动勾选启用 SHARD 分片时生效）
        if self.protocol == "shard" || self.enable_shard {
            cmd.env("AETHER_SHARD", "1");
            cmd.env("AETHER_FRAGMENT", "1");
            cmd.env("AETHER_SHARD_MODE", &self.shard_mode);

            if !self.shard_size.trim().is_empty() {
                cmd.env("AETHER_SHARD_SIZE", self.shard_size.trim());
                cmd.env("AETHER_FRAGMENT_SIZE", self.shard_size.trim());
            }
            if !self.shard_sleep_ms.trim().is_empty() {
                cmd.env("AETHER_SHARD_SLEEP", self.shard_sleep_ms.trim());
                cmd.env("AETHER_FRAGMENT_SLEEP", self.shard_sleep_ms.trim());
            }
            if !self.custom_sni.trim().is_empty() {
                cmd.env("AETHER_SNI", self.custom_sni.trim());
            }
        }

        // 3. ECH (Encrypted Client Hello) 配置
        if self.ech_mode == "auto" {
            cmd.env("AETHER_ECH", "auto");
        }

        // 4. 扫描与混淆通用配置
        cmd.env("AETHER_SCAN", &self.scan_mode);
        cmd.env("AETHER_NOIZE", &self.noize_profile);
        cmd.env("AETHER_IP", &self.ip_version);
        cmd.env("AETHER_SOCKS", self.socks_listen.trim());
        cmd.env("AETHER_QUICK_RECONNECT", "1");

        if !self.http_listen.trim().is_empty() {
            cmd.env("AETHER_HTTP_PROXY", self.http_listen.trim());
        }

        // 5. 自定义节点 (Outer / Inner Peer)
        let peer = self.custom_peer.trim();
        let inner = self.custom_inner_peer.trim();
        if !peer.is_empty() {
            match self.protocol.as_str() {
                "wg" => {
                    cmd.env("AETHER_WG_PEER", peer);
                }
                "gool" => {
                    cmd.env("AETHER_WIW_OUTER_PEER", peer);
                    if !inner.is_empty() {
                        cmd.env("AETHER_WIW_INNER_PEER", inner);
                    }
                }
                "mim" => {
                    cmd.env("AETHER_MIM_OUTER_PEER", peer);
                    if !inner.is_empty() {
                        cmd.env("AETHER_MIM_INNER_PEER", inner);
                    }
                }
                _ => {
                    cmd.env("AETHER_PEER", peer);
                }
            }
        }

        // 6. 链式代理配置 (Chain / Reverse)
        match self.chain_mode.as_str() {
            "psiphon_chain" => { cmd.env("AETHER_PSIPHON", "chain"); }
            "psiphon_reverse" => { cmd.env("AETHER_PSIPHON", "reverse"); }
            "tor_chain" => { cmd.env("AETHER_TOR", "chain"); }
            "tor_reverse" => { cmd.env("AETHER_TOR", "reverse"); }
            _ => {}
        }

        if self.bypass_lan_iran {
            cmd.env("AETHER_BYPASS_DIRECT", "1");
        }

        cmd.stdout(Stdio::piped()).stderr(Stdio::piped());

        #[cfg(target_os = "windows")]
        cmd.creation_flags(0x08000000); // 隐藏后台控制台窗口

        match cmd.spawn() {
            Ok(mut child) => {
                self.is_running = true;
                self.append_log(format!(
                    "[+] 正在启动核心 (协议: {} | 探测: {})...",
                    self.protocol.to_uppercase(),
                    self.scan_mode
                ));

                if self.sys_proxy {
                    self.set_windows_system_proxy(true);
                }

                let stdout = child.stdout.take();
                let stderr = child.stderr.take();
                *self.child_proc.lock().unwrap() = Some(child);

                if let Some(out) = stdout {
                    let logs = Arc::clone(&self.logs);
                    let ctx_clone = ctx.clone();
                    thread::spawn(move || {
                        for line in BufReader::new(out).lines().map_while(Result::ok) {
                            if let Ok(mut l) = logs.lock() {
                                l.push(line);
                            }
                            ctx_clone.request_repaint();
                        }
                    });
                }

                if let Some(err) = stderr {
                    let logs = Arc::clone(&self.logs);
                    let ctx_clone = ctx.clone();
                    thread::spawn(move || {
                        for line in BufReader::new(err).lines().map_while(Result::ok) {
                            if let Ok(mut l) = logs.lock() {
                                l.push(line);
                            }
                            ctx_clone.request_repaint();
                        }
                    });
                }
            }
            Err(e) => {
                self.append_log(format!("[-] 启动失败，请确认 aether.exe 在同一目录: {}", e));
            }
        }
    }

    fn stop_core(&mut self) {
        if let Ok(mut guard) = self.child_proc.lock() {
            if let Some(mut child) = guard.take() {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
        if self.sys_proxy {
            self.set_windows_system_proxy(false);
        }
        self.is_running = false;
        self.append_log("[*] 隧道已断开，服务已停止。");
    }
}

impl eframe::App for MsnGuardApp {
    fn on_exit(&mut self, _gl: Option<&eframe::glow::Context>) {
        if self.is_running {
            self.stop_core();
        }
    }

    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("🛡️ MSN-GUARD Windows 客户端");
            ui.separator();

            ui.add_enabled_ui(!self.is_running, |ui| {
                egui::Grid::new("settings_grid")
                    .num_columns(2)
                    .spacing([16.0, 9.0])
                    .striped(true)
                    .show(ui, |ui| {
                        // 1. 传输协议选择（含 SHARD 与 5 大通道）
                        ui.label("传输协议 (Transport):");
                        egui::ComboBox::from_id_salt("protocol_cb")
                            .width(340.0)
                            .selected_text(match self.protocol.as_str() {
                                "shard" => "⚡ SHARD (TLS 分片抗 DPI 封锁 / 推荐)",
                                "masque" => "MASQUE (QUIC/H3 现代高速通道)",
                                "wg" => "WireGuard (WARP + AetherNoize 混淆)",
                                "gool" => "WARP-in-WARP (Gool 双跳隧道)",
                                "mim" => "MASQUE-in-MASQUE (双跳变更出口)",
                                "psiphon_only" => "Psiphon 独立通道 (纯 Psiphon)",
                                "tor_only" => "Tor 独立通道 (纯 Tor 网络)",
                                _ => &self.protocol,
                            })
                            .show_ui(ui, |ui| {
                                if ui.selectable_value(&mut self.protocol, "shard".to_string(), "⚡ SHARD (TLS 分片抗 DPI 封锁 / 推荐)").clicked() {
                                    self.enable_shard = true;
                                    self.masque_carrier = "h2".to_string();
                                }
                                ui.selectable_value(&mut self.protocol, "masque".to_string(), "MASQUE (QUIC/H3 现代高速通道)");
                                ui.selectable_value(&mut self.protocol, "wg".to_string(), "WireGuard (WARP + AetherNoize 混淆)");
                                ui.selectable_value(&mut self.protocol, "gool".to_string(), "WARP-in-WARP (Gool 双跳隧道)");
                                ui.selectable_value(&mut self.protocol, "mim".to_string(), "MASQUE-in-MASQUE (双跳变更出口)");
                                ui.separator();
                                ui.selectable_value(&mut self.protocol, "psiphon_only".to_string(), "Psiphon 独立通道 (纯 Psiphon)");
                                ui.selectable_value(&mut self.protocol, "tor_only".to_string(), "Tor 独立通道 (纯 Tor 网络)");
                            });
                        ui.end_row();

                        // 2. MASQUE 载体模式
                        if self.protocol == "masque" || self.protocol == "mim" {
                            ui.label("MASQUE 载体:");
                            ui.horizontal(|ui| {
                                ui.radio_value(&mut self.masque_carrier, "h3".to_string(), "HTTP/3 (UDP/QUIC)");
                                ui.radio_value(&mut self.masque_carrier, "h2".to_string(), "HTTP/2 (TCP + 可开 SHARD)");
                                if self.masque_carrier == "h2" {
                                    ui.checkbox(&mut self.enable_shard, "开启 SHARD 分片");
                                }
                            });
                            ui.end_row();
                        }

                        // 3. SHARD 协议专属参数设置区
                        if self.protocol == "shard" || (self.masque_carrier == "h2" && self.enable_shard) {
                            ui.label("⚡ SHARD 分片策略:");
                            egui::ComboBox::from_id_salt("shard_mode_cb")
                                .selected_text(match self.shard_mode.as_str() {
                                    "tls" => "TLS Record 分片 + TCP 拆分 (标准 SHARD)",
                                    "sni" => "精准 SNI 边界切割 (对抗域名阻断)",
                                    "random" => "随机抖动分片 (对抗流量特征分析)",
                                    _ => &self.shard_mode,
                                })
                                .show_ui(ui, |ui| {
                                    ui.selectable_value(&mut self.shard_mode, "tls".to_string(), "TLS Record 分片 + TCP 拆分 (标准 SHARD)");
                                    ui.selectable_value(&mut self.shard_mode, "sni".to_string(), "精准 SNI 边界切割 (对抗域名阻断)");
                                    ui.selectable_value(&mut self.shard_mode, "random".to_string(), "随机抖动分片 (对抗流量特征分析)");
                                });
                            ui.end_row();

                            ui.label("⚡ SHARD 分片参数:");
                            ui.horizontal(|ui| {
                                ui.label("分片大小(字节):");
                                ui.add(egui::TextEdit::singleline(&mut self.shard_size).desired_width(50.0));
                                ui.label("分片间隔(ms):");
                                ui.add(egui::TextEdit::singleline(&mut self.shard_sleep_ms).desired_width(50.0));
                                ui.label("ECH:");
                                egui::ComboBox::from_id_salt("ech_cb")
                                    .width(75.0)
                                    .selected_text(&self.ech_mode)
                                    .show_ui(ui, |ui| {
                                        ui.selectable_value(&mut self.ech_mode, "off".to_string(), "off");
                                        ui.selectable_value(&mut self.ech_mode, "auto".to_string(), "auto");
                                    });
                            });
                            ui.end_row();

                            ui.label("⚡ 自定义 SNI (选填):");
                            ui.add(
                                egui::TextEdit::singleline(&mut self.custom_sni)
                                    .hint_text("留空使用默认混淆域名，或填写自定义 Fronting 域名"),
                            );
                            ui.end_row();
                        }

                        // 4. 节点探测模式
                        ui.label("节点探测模式 (Scan):");
                        egui::ComboBox::from_id_salt("scan_cb")
                            .selected_text(match self.scan_mode.as_str() {
                                "turbo" => "Turbo (极速，首命中)",
                                "balanced" => "Balanced (均衡默认)",
                                "thorough" => "Thorough (深度测速)",
                                "verified" => "Verified (仅内置实测节点 / 推荐)",
                                "ironclad" => "Ironclad (真机全链路 HTTP 校验)",
                                _ => &self.scan_mode,
                            })
                            .show_ui(ui, |ui| {
                                ui.selectable_value(&mut self.scan_mode, "verified".to_string(), "Verified (内置精选节点)");
                                ui.selectable_value(&mut self.scan_mode, "balanced".to_string(), "Balanced (均衡扫描)");
                                ui.selectable_value(&mut self.scan_mode, "turbo".to_string(), "Turbo (极速连接)");
                                ui.selectable_value(&mut self.scan_mode, "thorough".to_string(), "Thorough (深度优选)");
                                ui.selectable_value(&mut self.scan_mode, "ironclad".to_string(), "Ironclad (严格模式)");
                            });
                        ui.end_row();

                        // 5. DPI 混淆方案
                        ui.label("DPI 混淆强度 (Noize):");
                        egui::ComboBox::from_id_salt("noize_cb")
                            .selected_text(&self.noize_profile)
                            .show_ui(ui, |ui| {
                                ui.selectable_value(&mut self.noize_profile, "firewall".to_string(), "firewall (穿透防火墙)");
                                ui.selectable_value(&mut self.noize_profile, "balanced".to_string(), "balanced (均衡混淆)");
                                ui.selectable_value(&mut self.noize_profile, "aggressive".to_string(), "aggressive (强力对抗)");
                                ui.selectable_value(&mut self.noize_profile, "light".to_string(), "light (轻量)");
                                ui.selectable_value(&mut self.noize_profile, "off".to_string(), "off (关闭)");
                            });
                        ui.end_row();

                        // 6. IP 协议栈
                        ui.label("扫描 IP 版本:");
                        ui.horizontal(|ui| {
                            ui.radio_value(&mut self.ip_version, "4".to_string(), "IPv4");
                            ui.radio_value(&mut self.ip_version, "6".to_string(), "IPv6");
                            ui.radio_value(&mut self.ip_version, "both".to_string(), "双栈 (Both)");
                        });
                        ui.end_row();

                        // 7. 自定义节点
                        ui.label("指定节点 (选填):");
                        ui.add(
                            egui::TextEdit::singleline(&mut self.custom_peer)
                                .hint_text("留空则自动扫描内置节点，如 162.159.192.1:443"),
                        );
                        ui.end_row();

                        if self.protocol == "gool" || self.protocol == "mim" {
                            ui.label("第二跳节点 (选填):");
                            ui.add(
                                egui::TextEdit::singleline(&mut self.custom_inner_peer)
                                    .hint_text("留空则自动分配，如 188.114.96.1:443"),
                            );
                            ui.end_row();
                        }

                        // 8. 隧道串联模式 (Chain / Reverse)
                        if self.protocol != "psiphon_only" && self.protocol != "tor_only" {
                            ui.label("隧道嵌套串联 (Chain):");
                            egui::ComboBox::from_id_salt("chain_cb")
                                .selected_text(match self.chain_mode.as_str() {
                                    "none" => "不串联 (直连主协议网关)",
                                    "psiphon_chain" => "Psiphon 跑在隧道内 (WARP -> Psiphon)",
                                    "psiphon_reverse" => "隧道跑在 Psiphon 内 (Psiphon -> WARP)",
                                    "tor_chain" => "Tor 跑在隧道内 (WARP -> Tor)",
                                    "tor_reverse" => "隧道跑在 Tor 内 (Tor -> WARP)",
                                    _ => &self.chain_mode,
                                })
                                .show_ui(ui, |ui| {
                                    ui.selectable_value(&mut self.chain_mode, "none".to_string(), "不串联 (直连主协议网关)");
                                    ui.selectable_value(&mut self.chain_mode, "psiphon_chain".to_string(), "Psiphon 跑在隧道内 (--psiphon)");
                                    ui.selectable_value(&mut self.chain_mode, "psiphon_reverse".to_string(), "隧道跑在 Psiphon 内 (--psiphon-reverse)");
                                    ui.selectable_value(&mut self.chain_mode, "tor_chain".to_string(), "Tor 跑在隧道内 (--tor)");
                                    ui.selectable_value(&mut self.chain_mode, "tor_reverse".to_string(), "隧道跑在 Tor 内 (--tor-reverse)");
                                });
                            ui.end_row();
                        }

                        // 9. 本地端口与系统代理
                        ui.label("本地代理端口:");
                        ui.horizontal(|ui| {
                            ui.label("SOCKS5:");
                            ui.add(egui::TextEdit::singleline(&mut self.socks_listen).desired_width(115.0));
                            ui.label("HTTP:");
                            ui.add(egui::TextEdit::singleline(&mut self.http_listen).desired_width(115.0));
                        });
                        ui.end_row();

                        ui.label("系统与路由选项:");
                        ui.horizontal(|ui| {
                            ui.checkbox(&mut self.sys_proxy, "自动设置 Windows 系统代理");
                            ui.checkbox(&mut self.bypass_lan_iran, "绕过局域网与直连地址 (不破坏 SHARD)");
                        });
                        ui.end_row();
                    });
            });

            ui.add_space(10.0);

            // 启动 / 停止 按钮
            ui.vertical_centered(|ui| {
                if !self.is_running {
                    let btn = egui::Button::new(
                        egui::RichText::new("🚀 启动连接 (Connect)").size(16.0),
                    )
                    .min_size(egui::vec2(240.0, 40.0));
                    if ui.add(btn).clicked() {
                        self.start_core(ctx.clone());
                    }
                } else {
                    let btn = egui::Button::new(
                        egui::RichText::new("🛑 断开连接 (Disconnect)").size(16.0),
                    )
                    .min_size(egui::vec2(240.0, 40.0));
                    if ui.add(btn).clicked() {
                        self.stop_core();
                    }
                }
            });

            ui.add_space(6.0);
            ui.separator();

            ui.horizontal(|ui| {
                ui.label("📄 实时运行日志:");
                if ui.button("清空日志").clicked() {
                    if let Ok(mut logs) = self.logs.lock() {
                        logs.clear();
                    }
                }
            });

            // 底部滚动日志框
            egui::ScrollArea::vertical()
                .stick_to_bottom(true)
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    if let Ok(logs) = self.logs.lock() {
                        for line in logs.iter() {
                            ui.monospace(line);
                        }
                    }
                });
        });
    }
}
