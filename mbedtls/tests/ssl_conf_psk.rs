#![allow(dead_code)]
extern crate mbedtls;

use std::net::TcpStream;
use std::sync::Arc;

mod support;
use support::entropy::entropy_new;

use mbedtls::rng::CtrDrbg;
use mbedtls::ssl::config::{Endpoint, Preset, Transport};
use mbedtls::ssl::context::HandshakeContext;
use mbedtls::ssl::{Config, Context};
use mbedtls::Result as TlsResult;


fn client(conn: TcpStream, psk: &[u8]) -> TlsResult<()> {
    {
        let entropy = Arc::new(entropy_new());
        let rng = Arc::new(CtrDrbg::new(entropy, None)?);
        let mut config = Config::new(Endpoint::Client, Transport::Stream, Preset::Default);
        config.set_rng(rng);
        config.set_psk(psk, "Client_identity")?;
        let mut ctx = Context::new(Arc::new(config));
        ctx.establish(conn, None).map(|_| ())?;
        Ok(())
    }
}

fn server<F>(conn: TcpStream, mut psk_callback: F) -> TlsResult<()>
    where
        F: FnMut(&mut HandshakeContext, &str) -> TlsResult<()> {
    let entropy = entropy_new();
    let rng = Arc::new(CtrDrbg::new(Arc::new(entropy), None)?);
    let mut config = Config::new(Endpoint::Server, Transport::Stream, Preset::Default);
    config.set_rng(rng);
    config.set_psk_callback(&mut psk_callback);
    let mut ctx = Context::new(Arc::new(config));
    let _ = ctx.establish(conn, None)?;
    Ok(())
}

#[cfg(unix)]
mod test {
    use super::*;
    use std::thread;
    use crate::support::net::create_tcp_pair;
    use crate::support::keys;

    #[test]
    fn callback_standard_psk() {
        let (c, s) = create_tcp_pair().unwrap();
        let psk_callback =
            |ctx: &mut HandshakeContext, _: &str| { ctx.set_psk(keys::PRESHARED_KEY) };
        let c = thread::spawn(move || super::client(c, keys::PRESHARED_KEY).unwrap());
        let s = thread::spawn(move || super::server(s, psk_callback).unwrap());
        c.join().unwrap();
        s.join().unwrap();
    }
}
