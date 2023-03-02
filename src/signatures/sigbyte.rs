use log::info;

#[derive(Copy, Clone)]
pub enum SigByte {
    Wildcard,
    Match(u8),
}
impl SigByte
{
    pub fn to_str_generic(&self) -> String {
        match &self {
            SigByte::Wildcard => "?? ".to_owned(),
            SigByte::Match(value) => format!("{:02X} ", value),
        }
    }
    pub fn to_str_sm(&self) -> String {
        match &self {
            SigByte::Wildcard => "\\x2A".to_owned(),
            SigByte::Match(value) => format!("\\x{:02X}", value),
        }
    }
}

impl std::fmt::Debug for SigByte {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self {
            SigByte::Wildcard => f.write_str("??"),
            SigByte::Match(value) => f.write_fmt(format_args!("{:#02x}", value)),
        }
    }
}

pub fn parse_signature(string: String) -> Result<Vec<SigByte>, String>
{
    //  Remove whitespace before & after
    let trimmed = string.trim();

    //  Convert SM sigs to generic space-based
    let wildcarded = trimmed.replace("\\x2A", " ?? ");
    let spaced = wildcarded.replace("\\x", " ");

    let mut sig: Vec<SigByte> = Vec::new();

    for byte in spaced.split_whitespace().into_iter() {
        //info!("Parsing '{0}'", byte);

        let value = match byte
        {
            "??" => SigByte::Wildcard,
            "?" => SigByte::Wildcard,
            _ => {
                let parsed = u8::from_str_radix(byte, 16);
                match (parsed)
                {
                    Ok(parsed_value) => SigByte::Match(parsed_value),
                    Err(err) => return Err(format!("Failed to parse {0}: {1}", byte, err.to_string())),
                }
            },
        };

        //info!("Parsed '{0}' to '{1}'", byte, value.to_str_generic());

        sig.push(value);
    }

    return Ok(sig);
}