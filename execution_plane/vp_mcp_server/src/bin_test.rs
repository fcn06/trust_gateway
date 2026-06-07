fn main() {
    let url = "https://api.duckduckgo.com/?q=Carlos Alcaraz&format=json";
    let parsed = reqwest::Url::parse(url);
    println!("{:?}", parsed);
}
