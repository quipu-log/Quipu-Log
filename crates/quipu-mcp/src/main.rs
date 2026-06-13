//! `quipu-mcp` binary: run the MCP server over stdio, or issue a token.
//!
//! Usage:
//!   quipu-mcp serve         talk MCP on stdio to a quipu-server (config from env)
//!   quipu-mcp issue-token <role> [expires_unix_secs]
//!                           mint a scoped token and print the config line
//!
//! Serve reads its upstream from the environment so secrets stay out of argv
//! (and out of an MCP client's process table):
//!   QUIPU_SERVER_ADDR   host:port of the server's plain-HTTP listener (required)
//!   QUIPU_MCP_TOKEN     bearer token the agent's queries present (required)

use quipu_mcp::{HttpBackend, Server};
use std::io::Write;

fn usage() -> ! {
    eprintln!(
        "usage:\n  \
         quipu-mcp serve\n  \
         quipu-mcp issue-token <role> [expires_unix_secs]"
    );
    std::process::exit(2);
}

fn main() {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("serve") => serve(),
        Some("issue-token") => issue_token(args.next(), args.next()),
        _ => usage(),
    }
}

fn serve() -> ! {
    let addr = env_or_exit("QUIPU_SERVER_ADDR");
    let token = env_or_exit("QUIPU_MCP_TOKEN");
    let server = Server::new(HttpBackend::new(addr, token));
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    if let Err(e) = server.run_stdio(stdin.lock(), stdout.lock()) {
        eprintln!("quipu-mcp stdio loop ended: {e}");
        std::process::exit(1);
    }
    std::process::exit(0);
}

fn issue_token(role: Option<String>, expires: Option<String>) -> ! {
    let Some(role) = role else { usage() };
    let expires = match expires {
        None => None,
        Some(s) => match s.parse::<u64>() {
            Ok(n) => Some(n),
            Err(_) => {
                eprintln!("expires must be a unix-seconds integer");
                std::process::exit(2);
            }
        },
    };
    let issued = quipu_mcp::issuer::issue(&role, expires);
    let mut out = std::io::stdout().lock();
    // the token goes to the client once; the config line goes to the server
    let _ = writeln!(out, "token (give to the client, store nowhere else):\n  {}", issued.token);
    let _ = writeln!(out, "\nadd under auth.tokens in the server config:\n  {}", issued.config_entry());
    let _ = writeln!(
        out,
        "\nthen grant the role its scope under auth.grants, e.g.\n  \"{}\": [\"query\"]   (add \"administer\" to allow verify_store_integrity)",
        issued.role
    );
    std::process::exit(0);
}

fn env_or_exit(key: &str) -> String {
    match std::env::var(key) {
        Ok(v) if !v.is_empty() => v,
        _ => {
            eprintln!("missing required environment variable {key}");
            std::process::exit(2);
        }
    }
}
