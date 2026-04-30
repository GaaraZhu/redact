use serde::Serialize;

#[derive(Serialize)]
pub struct ErrorResponse {
    pub error: String,
}

pub fn exit_with_error(msg: &str) -> ! {
    let response = ErrorResponse {
        error: msg.to_string(),
    };
    println!("{}", serde_json::to_string(&response).unwrap());
    std::process::exit(1);
}
