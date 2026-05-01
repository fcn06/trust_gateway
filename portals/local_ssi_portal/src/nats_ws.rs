use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use web_sys::{WebSocket, MessageEvent};
use std::sync::{Arc, Mutex};

// A wrapper to make WebSocket Send + Sync (safe in single-threaded WASM)
#[derive(Clone)]
struct WsWrapper(WebSocket);
unsafe impl Send for WsWrapper {}
unsafe impl Sync for WsWrapper {}

/// A minimalist NATS WebSocket client for the Portal.
pub struct NatsWsClient {
    ws: Arc<Mutex<Option<WsWrapper>>>,
}

impl NatsWsClient {
    pub fn connect(url: &str, subject: &str, on_message: impl Fn() + Send + Sync + 'static) -> Result<Self, JsValue> {
        let ws = WebSocket::new(url)?;
        let ws_clone = Arc::new(Mutex::new(Some(WsWrapper(ws.clone()))));
        
        let on_message_cb = Arc::new(on_message);

        // onopen: send CONNECT and SUB
        let onopen_callback = {
            let ws = ws.clone();
            let subject = subject.to_string();
            Closure::wrap(Box::new(move |_| {
                let connect_cmd = r#"CONNECT {"verbose":false,"pedantic":false,"tls_required":false,"name":"portal","lang":"rust","version":"0.1","protocol":1}"#;
                let _ = ws.send_with_str(connect_cmd);
                let sub_cmd = format!("SUB {} 1", subject);
                let _ = ws.send_with_str(&sub_cmd);
            }) as Box<dyn FnMut(JsValue)>)
        };
        ws.set_onopen(Some(onopen_callback.as_ref().unchecked_ref()));
        onopen_callback.forget();

        // onmessage: handle PING, MSG
        let onmessage_callback = {
            let ws = ws.clone();
            Closure::wrap(Box::new(move |e: MessageEvent| {
                if let Ok(txt) = e.data().dyn_into::<js_sys::JsString>() {
                    let s: String = txt.into();
                    if s.starts_with("PING") {
                        let _ = ws.send_with_str("PONG");
                    } else if s.starts_with("MSG") {
                        // Trigger the callback when a message is received
                        on_message_cb();
                    }
                }
            }) as Box<dyn FnMut(MessageEvent)>)
        };
        ws.set_onmessage(Some(onmessage_callback.as_ref().unchecked_ref()));
        onmessage_callback.forget();

        // onerror and onclose
        let onclose_callback = Closure::wrap(Box::new(move |_| {
            web_sys::console::log_1(&"NATS WS Closed".into());
        }) as Box<dyn FnMut(JsValue)>);
        ws.set_onclose(Some(onclose_callback.as_ref().unchecked_ref()));
        onclose_callback.forget();

        Ok(Self { ws: ws_clone })
    }

    pub fn disconnect(&self) {
        if let Ok(mut lock) = self.ws.lock() {
            if let Some(wrapper) = lock.take() {
                let _ = wrapper.0.close();
            }
        }
    }
}
