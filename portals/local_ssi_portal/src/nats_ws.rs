use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use web_sys::{WebSocket, MessageEvent};
use std::sync::{Arc, Mutex};

// A wrapper to make WebSocket Send + Sync (safe in single-threaded WASM)
#[derive(Clone)]
struct WsWrapper(WebSocket);
unsafe impl Send for WsWrapper {}
unsafe impl Sync for WsWrapper {}

/// A minimalist NATS WebSocket client for the Portal with Exponential Backoff.
pub struct NatsWsClient {
    ws: Arc<Mutex<Option<WsWrapper>>>,
    url: String,
    subject: String,
    on_message: Arc<Box<dyn Fn(String) + Send + Sync + 'static>>,
    on_status: Arc<Box<dyn Fn(bool) + Send + Sync + 'static>>,
    reconnect_attempts: Arc<Mutex<u32>>,
}

impl NatsWsClient {
    pub fn connect(
        url: &str, 
        subject: &str, 
        on_message: impl Fn(String) + Send + Sync + 'static,
        on_status: impl Fn(bool) + Send + Sync + 'static
    ) -> Result<Arc<Self>, JsValue> {
        let client = Arc::new(Self {
            ws: Arc::new(Mutex::new(None)),
            url: url.to_string(),
            subject: subject.to_string(),
            on_message: Arc::new(Box::new(on_message)),
            on_status: Arc::new(Box::new(on_status)),
            reconnect_attempts: Arc::new(Mutex::new(0)),
        });

        client.do_connect()?;
        Ok(client)
    }

    fn do_connect(self: &Arc<Self>) -> Result<(), JsValue> {
        let ws = WebSocket::new(&self.url)?;
        let _ws_clone = Arc::new(Mutex::new(Some(WsWrapper(ws.clone()))));
        
        *self.ws.lock().unwrap() = Some(WsWrapper(ws.clone()));

        let subject = self.subject.clone();
        let on_status_cb = self.on_status.clone();
        let attempts_clone = self.reconnect_attempts.clone();
        let self_clone = self.clone();

        // onopen: send CONNECT and SUB, and reset retry counter
        let onopen_callback = {
            let ws = ws.clone();
            Closure::wrap(Box::new(move |_| {
                web_sys::console::log_1(&"✅ NATS WS Connected".into());
                *attempts_clone.lock().unwrap() = 0; // Reset attempts on success
                
                let connect_cmd = r#"CONNECT {"verbose":false,"pedantic":false,"tls_required":false,"name":"portal","lang":"rust","version":"0.1","protocol":1}"#;
                let _ = ws.send_with_str(connect_cmd);
                let sub_cmd = format!("SUB {} 1", subject);
                let _ = ws.send_with_str(&sub_cmd);
                
                on_status_cb(true);
            }) as Box<dyn FnMut(JsValue)>)
        };
        ws.set_onopen(Some(onopen_callback.as_ref().unchecked_ref()));
        onopen_callback.forget();

        // onmessage: handle PING, MSG
        let onmessage_callback = {
            let ws = ws.clone();
            let on_message_cb = self.on_message.clone();
            Closure::wrap(Box::new(move |e: MessageEvent| {
                if let Ok(txt) = e.data().dyn_into::<js_sys::JsString>() {
                    let s: String = txt.into();
                    if s.starts_with("PING") {
                        let _ = ws.send_with_str("PONG");
                    } else if s.starts_with("MSG") {
                        // NATS protocol for MSG: MSG <subject> <sid> [reply-to] <#bytes>\r\n<payload>\r\n
                        // This minimalist client expects the payload to follow in the same string or next.
                        // However, the proxy often sends them joined or we might need better parsing.
                        // For our proxy, we assume the payload is in the next lines.
                        let parts: Vec<&str> = s.splitn(2, "\r\n").collect();
                        if parts.len() > 1 {
                            let payload = parts[1].trim_end().to_string();
                            if !payload.is_empty() {
                                on_message_cb(payload);
                            }
                        }
                    }
                }
            }) as Box<dyn FnMut(MessageEvent)>)
        };
        ws.set_onmessage(Some(onmessage_callback.as_ref().unchecked_ref()));
        onmessage_callback.forget();

        // onerror and onclose: schedule reconnect
        let on_status_error = self.on_status.clone();
        let onclose_callback = Closure::wrap(Box::new(move |_| {
            web_sys::console::warn_1(&"⚠️ NATS WS Closed - Scheduling reconnect...".into());
            on_status_error(false);
            
            let mut attempts = self_clone.reconnect_attempts.lock().unwrap();
            let current_attempts = *attempts;
            let delay_ms = 1000 * (2_u32.pow(current_attempts.min(5))); // Max backoff 32s
            *attempts += 1;
            
            let window = web_sys::window().unwrap();
            let self_for_timeout = self_clone.clone();
            let timeout_cb = Closure::wrap(Box::new(move || {
                let _ = self_for_timeout.do_connect();
            }) as Box<dyn FnMut()>);
            
            window.set_timeout_with_callback_and_timeout_and_arguments_0(
                timeout_cb.as_ref().unchecked_ref(),
                delay_ms as i32,
            ).unwrap();
            timeout_cb.forget();
            
        }) as Box<dyn FnMut(JsValue)>);
        ws.set_onclose(Some(onclose_callback.as_ref().unchecked_ref()));
        ws.set_onerror(Some(onclose_callback.as_ref().unchecked_ref()));
        onclose_callback.forget();

        Ok(())
    }

    pub fn disconnect(&self) {
        if let Ok(mut lock) = self.ws.lock() {
            if let Some(wrapper) = lock.take() {
                // Clear callbacks to prevent auto-reconnect on manual disconnect
                wrapper.0.set_onclose(None);
                wrapper.0.set_onerror(None);
                let _ = wrapper.0.close();
            }
        }
    }
}

