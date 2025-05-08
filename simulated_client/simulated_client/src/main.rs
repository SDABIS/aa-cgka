// #[macro_use]
// extern crate clap;
// use clap::App;

use std::thread;
use simulated_client::client_agent::{ClientAgent};

use clap::{Arg, ArgAction, Command};
use config::Config;
use serde_json::Value;
use simulated_client::user_parameters::UserParameters;

/*const HELP: &str = "
>>> Available commands:
>>>     - update                                update the client state
>>>     - reset                                 reset the server
>>>     - register {client name}                register a new client
>>>     - save {client name}                    serialize and save the client state
>>>     - load {client name}                    load and deserialize the client state as a new client
>>>     - autosave                              enable automatic save of the current client state upon each update
>>>     - create kp                             create a new key package
>>>     - create group {group name}             create a new group
>>>     - group {group name}                    group operations
>>>         - send {message}                    send message to group
>>>         - invite {client name}              invite a user to the group
>>>         - read                              read messages sent to the group (max 100)
>>>         - update                            update the client state

";*/

fn main() {
    let matches = Command::new("OpenMLS Simulated Client")
        .version("0.1.0")
        .author("David Soler")
        .about("PoC MLS Delivery Service")
        .arg(
            Arg::new("name")
                .short('n')
                .long("name")
                .action(ArgAction::Append),
        ).arg(
        Arg::new("config-file")
            .short('c')
            .long("configuration file")
            .action(ArgAction::Append),
    )
        .get_matches();

    pretty_env_logger::init();

    let config_filename = matches.get_one::<String>("config-file").cloned().unwrap_or("simulated_client/resources/Settings.toml".to_string());
    let settings = Config::builder()
        // Add in `./Settings.toml`
        .add_source(config::File::with_name(&config_filename))
        // Add in settings from the environment (with a prefix of APP)
        // Eg.. `APP_DEBUG=1 ./target/app` would set the `debug` key
        .add_source(config::Environment::with_prefix("CGKA"))
        .build()
        .unwrap();

    let name = matches.get_one::<String>("name").unwrap_or(&"User_1".to_string()).clone();
    let replicas = settings.get_int("meta.replicas").unwrap_or(1);
    let parameters = UserParameters::new_from_settings(&settings).expect("Error parsing Configuration file");
    println!("{:?}", parameters);

    let mut users = ClientAgent::create_user_from_ds(parameters.clone(), replicas, name.clone())
        .expect("Error creating Delivery Services and users");

    let requirement_str = include_str!("../resources/requirement.json");
    let default_requirement: Value = serde_json::from_str(requirement_str).unwrap();

    let mut threads = vec![];

    for (user_name, user) in users.drain() {
        let client_agent = ClientAgent::new(
            user_name, parameters.clone()
        );

        let default_requirement = default_requirement.clone();
        let thread = thread::spawn(move || {
            client_agent.run(user, default_requirement);
        });
        threads.push(thread);
    }

    for thread in threads {
        thread.join().expect("Error with thread");
    }


}
