//! XCP-69 Vault Setup Tool - Main CLI Entry Point

use anyhow::Result;
use clap::Parser;

// Import command modules
use xcp69_setup::commands::*;

#[derive(Parser, Debug)]
#[command(name="xcp69_setup", about="XCP-69 Vault Tool: setup, patch funding txid, finalize dividends")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(clap::Subcommand, Debug)]
enum Commands {
    /// Initial setup: vanity grind vault, build funding PSBT, compose all parents
    Setup(SetupOpts),
    /// Patch parent PSBTs with real funding txid after funding tx confirms
    PatchFundingTxid(PatchOpts),
    /// Prepare funding: load existing bundle, scan fee wallet UTXOs, build funding PSBT
    PrepareFunding(PrepareFundingOpts),
    /// Finalize parent transactions: re-sign with real funding txid after funding confirms
    FinalizeParents(FinalizeOpts),
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Setup(o) => run_setup(o),
        Commands::PatchFundingTxid(o) => run_patch_funding_txid(o),
        Commands::PrepareFunding(o) => run_prepare_funding(o),
        Commands::FinalizeParents(o) => run_finalize_parents(o),
    }
}