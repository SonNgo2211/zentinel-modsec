use zentinel_modsec::ModSecurity;
use std::fs;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter("debug")
        .init();

    let mut rules_content = String::new();
    let base_path = "/home/whackers/Downloads/DVWA/config/modsec/config/";
    let files = [
        "modsecurity.conf",
        "crs-setup.conf",
        "../rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf"
    ];
    for f in &files {
        let path = format!("{}{}", base_path, f);
        let content = fs::read_to_string(&path).unwrap();
        rules_content.push_str(&content);
    }
    
    // Always enable the rule engine
    let mut final_rules_content = String::new();
    final_rules_content.push_str("SecRuleEngine On\n");
    final_rules_content.push_str(&rules_content);

    let modsec = match ModSecurity::from_string(&final_rules_content) {
        Ok(m) => m,
        Err(e) => {
            println!("Error parsing rules: {:?}", e);
            return Ok(());
        }
    };
    
    println!("Compiled rules: {}", modsec.rule_count());
    
    let mut tx = modsec.new_transaction();
    
    let uri = "/vulnerabilities/sqli/?id=1'+UNION+SELECT+1,2--&Submit=Submit";
    println!("Testing URI: {}", uri);
    
    tx.process_uri(uri, "GET", "HTTP/1.1").unwrap();
    tx.add_request_header("Host", "localhost").unwrap();
    tx.add_request_header("Accept", "*/*").unwrap();
    tx.add_request_header("Content-Type", "text/plain").unwrap();
    tx.process_request_headers().unwrap();
    
    tx.process_request_body().unwrap();

    if let Some(intervention) = tx.intervention() {
        println!("BLOCKED: {:?}", intervention);
    } else {
        println!("PASSED (not blocked)");
    }

    Ok(())
}


