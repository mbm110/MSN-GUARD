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
            .with_inner_size([560.0, 620.0])
            .with_min_inner_size([480.0, 500.0])
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

// 自动加载 Windows 系统的微软雅黑字体以支持中文显示
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
    protocol: String,
    masque_carrier: String,
    scan_mode: String,
    noize_profile: String,
    ip_version: String,
    custom_peer: String,
    custom_inner_peer: String,
    socks_listen: String,
    http_listen: String,
    enable_tor: bool,
    enable_psiphon: bool,
    sys_proxy: bool,

    is_running: bool,
    child_proc: Arc<Mutex<Option<Child>>>,
    logs: Arc<Mutex<Vec<String>>>,
}

impl Default for MsnGuardApp {
    fn default() -> Self {
        Self {
            protocol: "masque".to_string(),
            masque_carrier: "h3".to_string(),
            scan_mode: "verified".to_string(),
            noize_profile: "balanced".to_string(),
            ip_version: "4".to_string(),
            custom_peer: String::new(),
            custom_inner_peer: String::new(),
            socks_listen: "127.0.0.1:1819".to_string(),
            http_listen: "127.0.0.1:1820".to_string(),
            enable_tor: false,
            enable_psiphon: false,
            sys_proxy: true,

            is_running: false,
            child_proc: Arc::new(Mutex::new(None)),
            logs: Arc::new(Mutex::new(vec![
                "[*] 欢迎使用 MSN-GUARD Windows 客户端".to_string(),
                "[*] 请确保 aether.exe 与本程序在同一文件夹下".to_string(),
            ])),
        }
    }
}

impl MsnGuardApp {
    fn append_log(&self, msg: impl Into<String>) {
        if let Ok(mut logs) = self.logs.lock() {
            logs.push(msg.into());
            if logs.len() > 500 {
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

        cmd.env("AETHER_PROTOCOL", &self.protocol);
        cmd.env("AETHER_SCAN", &self.scan_mode);
        cmd.env("AETHER_NOIZE", &self.noize_profile);
        cmd.env("AETHER_IP", &self.ip_version);
        cmd.env("AETHER_SOCKS", self.socks_listen.trim());
        cmd.env("AETHER_QUICK_RECONNECT", "1");

        if !self.http_listen.trim().is_empty() {
            cmd.env("AETHER_HTTP_PROXY", self.http_listen.trim());
        }

        if self.protocol == "masque" || self.protocol == "mim" {
            if self.masque_carrier == "h2" {
                cmd.env("AETHER_MASQUE_HTTP2", "1");
            }
        }

        let peer = self.custom_peer.trim();
        let inner = self.custom_inner_peer.trim();
        if !peer.is_empty() {
            match self.protocol.as_str() {
                "wg" => { cmd.env("AETHER_WG_PEER", peer); }
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
                _ => { cmd.env("AETHER_PEER", peer); }
            }
        }

        if self.enable_tor {
            cmd.env("AETHER_TOR", "chain");
        }
        if self.enable_psiphon {
            cmd.env("AETHER_PSIPHON", "chain");
        }

        cmd.stdout(Stdio::piped()).stderr(Stdio::piped());

        #[cfg(target_os = "windows")]
        cmd.creation_flags(0x08000000); // 隐藏后台黑框

        match cmd.spawn() {
            Ok(mut child) => {
                self.is_running = true;
                self.append_log("[+] 正在启动 Aether 核心...");

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
                self.append_log(format!("[-] 启动失败，请确认 aether.exe 是否在同一目录: {}", e));
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
                    .spacing([16.0, 10.0])
                    .striped(true)
                    .show(ui, |ui| {
                        // 1. 传输协议选择
                        ui.label("传输协议 (Protocol):");
                        egui::ComboBox::from_id_salt("protocol_cb")
                            .selected_text(match self.protocol.as_str() {
                                "masque" => "MASQUE (QUIC/H3 现代抗封锁)",
                                "wg" => "WireGuard (WARP 经典高速)",
                                "gool" => "WARP-in-WARP (Gool 双跳)",
                                "mim" => "MASQUE-in-MASQUE (双跳变出口)",
                                _ => &self.protocol,
                            })
                            .show_ui(ui, |ui| {
                                ui.selectable_value(&mut self.protocol, "masque".to_string(), "MASQUE (推荐)");
                                ui.selectable_value(&mut self.protocol, "wg".to_string(), "WireGuard (WARP)");
                                ui.selectable_value(&mut self.protocol, "gool".to_string(), "WARP-in-WARP (Gool)");
                                ui.selectable_value(&mut self.protocol, "mim".to_string(), "MASQUE-in-MASQUE");
                            });
                        ui.end_row();

                        // 2. MASQUE 载体模式
                        if self.protocol == "masque" || self.protocol == "mim" {
                            ui.label("MASQUE 传输层:");
                            ui.horizontal(|ui| {
                                ui.radio_value(&mut self.masque_carrier, "h3".to_string(), "HTTP/3 (UDP/QUIC)");
                                ui.radio_value(&mut self.masque_carrier, "h2".to_string(), "HTTP/2 (TCP 伪装)");
                            });
                            ui.end_row();
                        }

                        // 3. 节点扫描模式
                        ui.label("节点探测模式 (Scan):");
                        egui::ComboBox::from_id_salt("scan_cb")
                            .selected_text(match self.scan_mode.as_str() {
                                "turbo" => "Turbo (极速，首命中)",
                                "balanced" => "Balanced (均衡默认)",
                                "thorough" => "Thorough (深度测速)",
                                "verified" => "Verified (仅内置实测节点)",
                                "ironclad" => "Ironclad (真机全链路校验)",
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

                        // 4. 混淆强度
                        ui.label("DPI 混淆方案 (Noize):");
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

                        // 5. IP 协议版本
                        ui.label("扫描 IP 版本:");
                        ui.horizontal(|ui| {
                            ui.radio_value(&mut self.ip_version, "4".to_string(), "IPv4");
                            ui.radio_value(&mut self.ip_version, "6".to_string(), "IPv6");
                            ui.radio_value(&mut self.ip_version, "both".to_string(), "双栈 (Both)");
                        });
                        ui.end_row();

                        // 6. 自定义节点
                        ui.label("指定节点 (选填):");
                        ui.add(
                            egui::TextEdit::singleline(&mut self.custom_peer)
                                .hint_text("留空则自动扫描，格式如 162.159.192.1:443"),
                        );
                        ui.end_row();

                        if self.protocol == "gool" || self.protocol == "mim" {
                            ui.label("第二跳节点 (选填):");
                            ui.add(
                                egui::TextEdit::singleline(&mut self.custom_inner_peer)
                                    .hint_text("留空则自动分配，格式如 188.114.96.1:443"),
                            );
                            ui.end_row();
                        }

                        // 7. 本地代理端口
                        ui.label("本地 SOCKS5 端口:");
                        ui.text_edit_singleline(&mut self.socks_listen);
                        ui.end_row();

                        ui.label("本地 HTTP 端口:");
                        ui.text_edit_singleline(&mut self.http_listen);
                        ui.end_row();

                        // 8. 附加链式代理与系统代理
                        ui.label("附加选项:");
                        ui.vertical(|ui| {
                            ui.checkbox(&mut self.sys_proxy, "连接后自动设置 Windows 系统代理");
                            ui.checkbox(&mut self.enable_psiphon, "串联 Psiphon 隧道 (--psiphon)");
                            ui.checkbox(&mut self.enable_tor, "串联 Tor 隧道 (--tor)");
                        });
                        ui.end_row();
                    });
            });

            ui.add_space(12.0);

            // 启动 / 停止 按钮
            ui.vertical_centered(|ui| {
                if !self.is_running {
                    let btn = egui::Button::new(
                        egui::RichText::new("🚀 启动连接 (Connect)").size(16.0),
                    )
                    .min_size(egui::vec2(220.0, 42.0));
                    if ui.add(btn).clicked() {
                        self.start_core(ctx.clone());
                    }
                } else {
                    let btn = egui::Button::new(
                        egui::RichText::new("🛑 断开连接 (Disconnect)").size(16.0),
                    )
                    .min_size(egui::vec2(220.0, 42.0));
                    if ui.add(btn).clicked() {
                        self.stop_core();
                    }
                }
            });

            ui.add_space(8.0);
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
