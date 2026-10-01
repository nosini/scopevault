//! Static description of the interfaces the service implements.
//!
//! One table drives both request validation (argument signatures, property
//! access) and the introspection XML, so the two cannot disagree. Members
//! follow the Secret Service specification (xdg-specs
//! `secret-service/org.freedesktop.Secrets.xml`) and the D-Bus specification
//! for the standard interfaces.

pub struct Method {
    pub name: &'static str,
    /// (name, signature) of input arguments.
    pub args_in: &'static [(&'static str, &'static str)],
    pub args_out: &'static [(&'static str, &'static str)],
}

impl Method {
    /// The concatenated input signature, as it appears in a message body.
    pub fn in_signature(&self) -> String {
        self.args_in.iter().map(|(_, s)| *s).collect()
    }
}

pub struct Property {
    pub name: &'static str,
    pub signature: &'static str,
    pub writable: bool,
}

pub struct Signal {
    pub name: &'static str,
    pub args: &'static [(&'static str, &'static str)],
}

pub struct Interface {
    pub name: &'static str,
    pub methods: &'static [Method],
    pub properties: &'static [Property],
    pub signals: &'static [Signal],
}

impl Interface {
    pub fn method(&self, name: &str) -> Option<&Method> {
        self.methods.iter().find(|m| m.name == name)
    }

    pub fn property(&self, name: &str) -> Option<&Property> {
        self.properties.iter().find(|p| p.name == name)
    }
}

macro_rules! args {
    ($($n:literal : $s:literal),* $(,)?) => { &[$(($n, $s)),*] };
}

pub const SERVICE: Interface = Interface {
    name: "org.freedesktop.Secret.Service",
    methods: &[
        Method {
            name: "OpenSession",
            args_in: args!["algorithm": "s", "input": "v"],
            args_out: args!["output": "v", "result": "o"],
        },
        Method {
            name: "CreateCollection",
            args_in: args!["properties": "a{sv}", "alias": "s"],
            args_out: args!["collection": "o", "prompt": "o"],
        },
        Method {
            name: "SearchItems",
            args_in: args!["attributes": "a{ss}"],
            args_out: args!["unlocked": "ao", "locked": "ao"],
        },
        Method { name: "Unlock", args_in: args!["objects": "ao"], args_out: args!["unlocked": "ao", "prompt": "o"] },
        Method { name: "Lock", args_in: args!["objects": "ao"], args_out: args!["locked": "ao", "Prompt": "o"] },
        Method {
            name: "GetSecrets",
            args_in: args!["items": "ao", "session": "o"],
            args_out: args!["secrets": "a{o(oayays)}"],
        },
        Method { name: "ReadAlias", args_in: args!["name": "s"], args_out: args!["collection": "o"] },
        Method { name: "SetAlias", args_in: args!["name": "s", "collection": "o"], args_out: args![] },
    ],
    properties: &[Property { name: "Collections", signature: "ao", writable: false }],
    signals: &[
        Signal { name: "CollectionCreated", args: args!["collection": "o"] },
        Signal { name: "CollectionDeleted", args: args!["collection": "o"] },
        Signal { name: "CollectionChanged", args: args!["collection": "o"] },
    ],
};

pub const COLLECTION: Interface = Interface {
    name: "org.freedesktop.Secret.Collection",
    methods: &[
        Method { name: "Delete", args_in: args![], args_out: args!["prompt": "o"] },
        Method { name: "SearchItems", args_in: args!["attributes": "a{ss}"], args_out: args!["results": "ao"] },
        Method {
            name: "CreateItem",
            args_in: args!["properties": "a{sv}", "secret": "(oayays)", "replace": "b"],
            args_out: args!["item": "o", "prompt": "o"],
        },
    ],
    properties: &[
        Property { name: "Items", signature: "ao", writable: false },
        Property { name: "Label", signature: "s", writable: true },
        Property { name: "Locked", signature: "b", writable: false },
        Property { name: "Created", signature: "t", writable: false },
        Property { name: "Modified", signature: "t", writable: false },
    ],
    signals: &[
        Signal { name: "ItemCreated", args: args!["item": "o"] },
        Signal { name: "ItemDeleted", args: args!["item": "o"] },
        Signal { name: "ItemChanged", args: args!["item": "o"] },
    ],
};

pub const ITEM: Interface = Interface {
    name: "org.freedesktop.Secret.Item",
    methods: &[
        Method { name: "Delete", args_in: args![], args_out: args!["Prompt": "o"] },
        Method { name: "GetSecret", args_in: args!["session": "o"], args_out: args!["secret": "(oayays)"] },
        Method { name: "SetSecret", args_in: args!["secret": "(oayays)"], args_out: args![] },
    ],
    properties: &[
        Property { name: "Locked", signature: "b", writable: false },
        Property { name: "Attributes", signature: "a{ss}", writable: true },
        Property { name: "Label", signature: "s", writable: true },
        Property { name: "Created", signature: "t", writable: false },
        Property { name: "Modified", signature: "t", writable: false },
    ],
    signals: &[],
};

pub const SESSION: Interface = Interface {
    name: "org.freedesktop.Secret.Session",
    methods: &[Method { name: "Close", args_in: args![], args_out: args![] }],
    properties: &[],
    signals: &[],
};

pub const PROMPT: Interface = Interface {
    name: "org.freedesktop.Secret.Prompt",
    methods: &[
        Method { name: "Prompt", args_in: args!["window-id": "s"], args_out: args![] },
        Method { name: "Dismiss", args_in: args![], args_out: args![] },
    ],
    properties: &[],
    signals: &[Signal { name: "Completed", args: args!["dismissed": "b", "result": "v"] }],
};

pub const PROPERTIES: Interface = Interface {
    name: "org.freedesktop.DBus.Properties",
    methods: &[
        Method {
            name: "Get",
            args_in: args!["interface_name": "s", "property_name": "s"],
            args_out: args!["value": "v"],
        },
        Method { name: "GetAll", args_in: args!["interface_name": "s"], args_out: args!["props": "a{sv}"] },
        Method {
            name: "Set",
            args_in: args!["interface_name": "s", "property_name": "s", "value": "v"],
            args_out: args![],
        },
    ],
    properties: &[],
    signals: &[Signal {
        name: "PropertiesChanged",
        args: args!["interface_name": "s", "changed_properties": "a{sv}", "invalidated_properties": "as"],
    }],
};

pub const INTROSPECTABLE: Interface = Interface {
    name: "org.freedesktop.DBus.Introspectable",
    methods: &[Method { name: "Introspect", args_in: args![], args_out: args!["xml_data": "s"] }],
    properties: &[],
    signals: &[],
};

pub const PEER: Interface = Interface {
    name: "org.freedesktop.DBus.Peer",
    methods: &[
        Method { name: "Ping", args_in: args![], args_out: args![] },
        Method { name: "GetMachineId", args_in: args![], args_out: args!["machine_uuid": "s"] },
    ],
    properties: &[],
    signals: &[],
};

/// Interfaces present on every object we expose.
pub const STANDARD: &[&Interface] = &[&PROPERTIES, &INTROSPECTABLE, &PEER];

const DOCTYPE: &str = "<!DOCTYPE node PUBLIC \"-//freedesktop//DTD D-BUS Object Introspection 1.0//EN\"\n \"http://www.freedesktop.org/standards/dbus/1.0/introspect.dtd\">\n";

/// Introspection XML for one node. `children` must already be filtered to
/// what the caller may see; names must be valid path elements (they are
/// generated by us, never taken from clients).
pub fn introspect(interfaces: &[&Interface], children: &[String]) -> String {
    use std::fmt::Write;
    let mut x = String::from(DOCTYPE);
    x.push_str("<node>\n");
    for iface in STANDARD.iter().chain(interfaces.iter()) {
        let _ = writeln!(x, "  <interface name=\"{}\">", iface.name);
        for m in iface.methods {
            let _ = writeln!(x, "    <method name=\"{}\">", m.name);
            for (n, s) in m.args_in {
                let _ = writeln!(x, "      <arg name=\"{n}\" type=\"{s}\" direction=\"in\"/>");
            }
            for (n, s) in m.args_out {
                let _ = writeln!(x, "      <arg name=\"{n}\" type=\"{s}\" direction=\"out\"/>");
            }
            x.push_str("    </method>\n");
        }
        for s in iface.signals {
            let _ = writeln!(x, "    <signal name=\"{}\">", s.name);
            for (n, sig) in s.args {
                let _ = writeln!(x, "      <arg name=\"{n}\" type=\"{sig}\"/>");
            }
            x.push_str("    </signal>\n");
        }
        for p in iface.properties {
            let access = if p.writable { "readwrite" } else { "read" };
            let _ = writeln!(x, "    <property name=\"{}\" type=\"{}\" access=\"{access}\"/>", p.name, p.signature);
        }
        x.push_str("  </interface>\n");
    }
    for c in children {
        debug_assert!(c.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_'));
        let _ = writeln!(x, "  <node name=\"{c}\"/>");
    }
    x.push_str("</node>\n");
    x
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every member in the upstream specification XML must be in our table
    /// with the same signatures, and vice versa.
    #[test]
    fn matches_upstream_specification() {
        let xml = include_str!("../../spec/org.freedesktop.Secrets.xml");
        let ours = [&SERVICE, &COLLECTION, &ITEM, &SESSION, &PROMPT];
        let mut upstream = Vec::new();
        let mut iface = String::new();
        let mut member = String::new();
        let mut kind = "";
        for raw in xml.lines() {
            let line = raw.trim();
            let attr = |name: &str| -> Option<String> {
                let start = line
                    .find(&format!("{name}=\""))
                    .map(|i| (i + name.len() + 2, '"'))
                    .or_else(|| line.find(&format!("{name}='")).map(|i| (i + name.len() + 2, '\'')))?;
                let rest = &line[start.0..];
                Some(rest[..rest.find(start.1)?].to_owned())
            };
            if line.starts_with("<interface") {
                iface = attr("name").unwrap();
            } else if line.starts_with("<method") || line.starts_with("<signal") {
                member = attr("name").unwrap();
                kind = if line.starts_with("<method") { "method" } else { "signal" };
                upstream.push(format!("{iface} {kind} {member}"));
            } else if line.starts_with("<property") {
                let access = attr("access").unwrap();
                upstream.push(format!("{iface} property {} {} {access}", attr("name").unwrap(), attr("type").unwrap()));
            } else if line.starts_with("<arg") {
                let dir = attr("direction").unwrap_or_else(|| "out".into());
                upstream.push(format!("{iface} {kind} {member} {dir} {}", attr("type").unwrap()));
            }
        }
        let mut mine = Vec::new();
        for i in ours {
            for m in i.methods {
                mine.push(format!("{} method {}", i.name, m.name));
                for (_, s) in m.args_in {
                    mine.push(format!("{} method {} in {s}", i.name, m.name));
                }
                for (_, s) in m.args_out {
                    mine.push(format!("{} method {} out {s}", i.name, m.name));
                }
            }
            for s in i.signals {
                mine.push(format!("{} signal {}", i.name, s.name));
                for (_, sig) in s.args {
                    mine.push(format!("{} signal {} out {sig}", i.name, s.name));
                }
            }
            for p in i.properties {
                let access = if p.writable { "readwrite" } else { "read" };
                mine.push(format!("{} property {} {} {access}", i.name, p.name, p.signature));
            }
        }
        upstream.sort();
        mine.sort();
        assert_eq!(upstream, mine);
    }

    #[test]
    fn introspection_lists_only_given_children() {
        let x = introspect(&[&SERVICE], &["a1".into()]);
        assert!(x.contains("<node name=\"a1\"/>"));
        assert!(x.contains("org.freedesktop.Secret.Service"));
        assert_eq!(x.matches("<node name=").count(), 1);
    }
}
