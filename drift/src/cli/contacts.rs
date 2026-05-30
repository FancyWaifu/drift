//! `drift contacts` subcommand — manage the local petname →
//! pubkey address book that all DRIFT-based tools share.

use super::ContactsArgs;
use anyhow::{anyhow, Context, Result};
use drift::contacts::{self_name, Contacts};
use std::net::SocketAddr;

pub async fn run(args: &ContactsArgs) -> Result<()> {
    match &args.command {
        ContactsCommand::List => list().await,
        ContactsCommand::Resolve { name } => resolve(name).await,
        ContactsCommand::Add { name, pubkey, addr } => add(name, pubkey, addr).await,
        ContactsCommand::Rename { old, new } => rename(old, new).await,
        ContactsCommand::Forget { name } => forget(name).await,
        ContactsCommand::SetName { name } => set_self_name(name).await,
        ContactsCommand::GetName => get_self_name().await,
        ContactsCommand::ClearName => clear_self_name().await,
        ContactsCommand::Path => print_path().await,
    }
}

#[derive(clap::Subcommand)]
pub enum ContactsCommand {
    /// Show every contact: petname, pubkey prefix, last-known
    /// address, when last seen.
    List,
    /// Resolve a petname to its pubkey + address (machine-
    /// readable form for shell scripts).
    Resolve {
        /// Petname to look up. `.drift` suffix is optional.
        name: String,
    },
    /// Manually add a contact with an explicit petname.
    /// Useful when someone shares a `pubkey@addr` and you
    /// want to skip the auto-add flow.
    Add {
        /// Local petname (becomes a typeable address-book key).
        name: String,
        /// Pubkey hex (64 chars).
        pubkey: String,
        /// Last-known address `host:port`.
        addr: String,
    },
    /// Rename an existing contact's petname.
    Rename {
        /// Current petname.
        old: String,
        /// New petname (must not collide with another contact).
        new: String,
    },
    /// Remove a contact from the address book.
    Forget {
        /// Petname of the contact to forget.
        name: String,
    },
    /// Set THIS user's self-advertised name. DRIFT tools that
    /// advertise to peers (drift-mosh-server, drift-http
    /// serve, drift-wormhole send) will use it.
    SetName {
        /// New self-name.
        name: String,
    },
    /// Show this user's currently-configured self-name.
    GetName,
    /// Remove the configured self-name (peers won't see one).
    ClearName,
    /// Print the path of the contacts file (handy for inspection
    /// or shell completion).
    Path,
}

async fn list() -> Result<()> {
    let c = Contacts::load_default()?;
    if c.list().is_empty() {
        eprintln!("no contacts saved yet");
        return Ok(());
    }
    println!(
        "{:<30}  {:<18}  {:<18}  ADVERTISED",
        "PETNAME", "PUBKEY (8B)", "ADDRESS"
    );
    for entry in c.list() {
        let pub_short = entry.pubkey.chars().take(16).collect::<String>();
        let advertised = entry.advertised_name.as_deref().unwrap_or("-");
        println!(
            "{:<30}  {:<18}  {:<18}  {}",
            entry.assigned_name, pub_short, entry.address, advertised
        );
    }
    Ok(())
}

async fn resolve(name: &str) -> Result<()> {
    let c = Contacts::load_default()?;
    let entry = c
        .resolve(name)
        .ok_or_else(|| anyhow!("no contact named {:?}", name))?;
    println!("PUBKEY={}", entry.pubkey);
    println!("ADDRESS={}", entry.address);
    if let Some(adv) = &entry.advertised_name {
        println!("ADVERTISED_NAME={}", adv);
    }
    Ok(())
}

async fn add(name: &str, pubkey: &str, addr: &str) -> Result<()> {
    let pk = drift::contacts::parse_pubkey_hex(pubkey)?;
    let socket: SocketAddr = addr
        .parse()
        .with_context(|| format!("address {:?} is not host:port", addr))?;
    let mut c = Contacts::load_default()?;
    c.add_manual(name, pk, socket)?;
    c.save()?;
    eprintln!("added {} ({})", name, addr);
    Ok(())
}

async fn rename(old: &str, new: &str) -> Result<()> {
    let mut c = Contacts::load_default()?;
    c.rename(old, new)?;
    c.save()?;
    eprintln!("renamed {} → {}", old, new);
    Ok(())
}

async fn forget(name: &str) -> Result<()> {
    let mut c = Contacts::load_default()?;
    c.forget(name)?;
    c.save()?;
    eprintln!("forgot {}", name);
    Ok(())
}

async fn set_self_name(name: &str) -> Result<()> {
    self_name::set(name)?;
    eprintln!("self-name: {}", name);
    Ok(())
}

async fn get_self_name() -> Result<()> {
    match self_name::load()? {
        Some(n) => println!("{}", n),
        None => eprintln!("(no self-name set; use `drift contacts set-name <NAME>` to set one)"),
    }
    Ok(())
}

async fn clear_self_name() -> Result<()> {
    self_name::clear()?;
    eprintln!("self-name cleared");
    Ok(())
}

async fn print_path() -> Result<()> {
    println!("{}", Contacts::default_path()?.display());
    Ok(())
}
