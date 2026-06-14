use configuration::AgentConfig;
use ssi_identity_agent::business_logic::ssi_identity_agent::SsiIdentityAgent;
use agent_core::business_logic::agent::Agent;
use ssi_identity_agent::secure_agent_server::SecureAgentServer;
use ssi_identity_agent::auth_config::AuthConfig;


use clap::Parser;
use std::env;

use configuration::setup_logging;

/// Command-line arguments for the identity agent server
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Configuration file path (TOML format)
    #[clap(long, default_value = "configuration/agent_identity_config.toml")]
    config_file: String,
    #[clap(long, default_value = "warn")]
    log_level: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {

    // Load environment variables
    let _ = dotenvy::dotenv();
    
    // Parse command-line arguments
    let args = Args::parse();

    /************************************************/
    /* Setting proper log level                     */
    /************************************************/ 
    setup_logging(&args.log_level);

    /************************************************/
    /* End of Setting proper log level              */
    /************************************************/ 

    /************************************************/
    /* Loading A2A Config File and launching        */
    /* A2A agent server                             */
    /************************************************/ 

    // load a2a config file and initialize appropriateruntime
    let identity_agent_config = AgentConfig::load_agent_config(&args.config_file).expect("Incorrect Identity Agent config file");
  
    let agent_api_key_wrapper = identity_context::load_secret("LLM_A2A_API_KEY")
        .expect("LLM_A2A_API_KEY must be set");
    let agent_api_key = agent_api_key_wrapper.expose_secret().to_string();

    let agent = SsiIdentityAgent::new(identity_agent_config.clone(),agent_api_key, None,None, None,None,None).await?;


    // Auth is handled at the host level (ACL + JWT minting) before dispatch.
    // The ssi_agent is localhost-only, so no HTTP-level auth is needed.
    let auth_config = AuthConfig::None;


    let authenticated_agent_server = SecureAgentServer::<SsiIdentityAgent>::new(identity_agent_config, agent,auth_config,None, None).await?;
    println!("🌐 Starting HTTP server for Identity Agent...");
    authenticated_agent_server.start_http().await?;

    /************************************************/
    /* A2A agent server launched                    */
    /* Responding to any A2A CLient                 */
    /************************************************/ 

    Ok(())
}
