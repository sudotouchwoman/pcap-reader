use users::{get_current_uid, get_user_by_uid};

fn greet(name: &str) -> String {
    format!("Greetings, {}", name)
}

fn main () {
    let user: String = get_user_by_uid(get_current_uid())
        .map(|user| user.name().to_string_lossy().into_owned())
        .unwrap_or_else(|| "anon".to_string());

    println!("{}", greet(user.as_str()))
}