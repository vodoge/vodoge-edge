#!/usr/bin/env python3
"""Generate Rust, Go, and TypeScript types from the edge-cloud JSON Schema.

The JSON Schema is the only source of truth. Generated files must be committed
and regenerated in CI; a drift diff fails the build.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SCHEMA = ROOT / "schema" / "edge-cloud.v1.schema.json"


def load_schema(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def rust_ident(name: str) -> str:
    mapping = {
        "v": "v",
        "id": "id",
        "ts": "ts",
        "seq": "seq",
        "type": "type_",
    }
    if name in mapping:
        return mapping[name]
    return name


def go_ident(name: str) -> str:
    parts = name.split("_")
    ident = "".join(p[:1].upper() + p[1:] for p in parts if p)
    if ident == "Id":
        return "ID"
    if ident.endswith("Id") and ident != "Id":
        ident = ident[:-2] + "ID"
    if ident == "V":
        return "V"
    if ident == "Ts":
        return "Ts"
    return ident


def ts_ident(name: str) -> str:
    return name


def is_u64_decimal(schema: dict) -> bool:
    return schema.get("x-vodoge-wire-type") == "u64-decimal"


def resolve(schema: dict, defs: dict) -> dict:
    if "$ref" in schema:
        ref = schema["$ref"]
        if not ref.startswith("#/$defs/"):
            raise SystemExit(f"unsupported $ref {ref}")
        return defs[ref.split("/")[-1]]
    return schema


def rust_type(schema: dict, defs: dict) -> str:
    if is_u64_decimal(schema):
        return "u64"
    if "$ref" in schema:
        name = schema["$ref"].split("/")[-1]
        target = defs[name]
        if is_u64_decimal(target):
            return "u64"
        if name in {"Uuid", "Iccid", "Imei", "Sha256", "HttpsUrl", "NullableString"}:
            if name == "NullableString":
                return "Option<String>"
            return "String"
        if name == "EpochMillis":
            return "i64"
        return name
    if "anyOf" in schema:
        non_null = [item for item in schema["anyOf"] if item.get("type") != "null"]
        if len(schema["anyOf"]) == 2 and len(non_null) == 1:
            inner = rust_type(non_null[0], defs)
            if inner.startswith("Option<"):
                return inner
            return f"Option<{inner}>"
        return "ContextValue"
    if schema.get("enum") and schema.get("type") == "string":
        return "String"
    if "const" in schema:
        return "String"
    types = schema.get("type")
    if types == "string":
        return "String"
    if types == "boolean":
        return "bool"
    if types == "integer":
        return "i64"
    if types == "number":
        return "f64"
    if types == "object":
        return "ContextValue"
    if types == "array":
        return f"Vec<{rust_type(schema.get('items', {}), defs)}>"
    if types == ["string", "null"]:
        return "Option<String>"
    return "ContextValue"


def go_type(schema: dict, defs: dict) -> str:
    if is_u64_decimal(schema):
        return "string"
    if "$ref" in schema:
        name = schema["$ref"].split("/")[-1]
        target = defs[name]
        if is_u64_decimal(target):
            return "string"
        if name in {"Uuid", "Iccid", "Imei", "Sha256", "HttpsUrl"}:
            return "string"
        if name == "NullableString":
            return "*string"
        if name == "EpochMillis":
            return "int64"
        if name == "ContextValue":
            return "any"
        return name
    if "anyOf" in schema:
        non_null = [item for item in schema["anyOf"] if item.get("type") != "null"]
        if len(schema["anyOf"]) == 2 and len(non_null) == 1:
            inner = go_type(non_null[0], defs)
            if inner.startswith("*"):
                return inner
            if inner == "string":
                return "*string"
            if inner == "int64":
                return "*int64"
            return "*" + inner
        return "any"
    types = schema.get("type")
    if types == "string" or "const" in schema or schema.get("enum"):
        return "string"
    if types == "boolean":
        return "bool"
    if types == "integer":
        return "int64"
    if types == "number":
        return "float64"
    if types == "array":
        return "[]" + go_type(schema.get("items", {}), defs)
    if types == ["string", "null"]:
        return "*string"
    return "any"


def ts_type(schema: dict, defs: dict) -> str:
    if is_u64_decimal(schema):
        return "string"
    if "$ref" in schema:
        name = schema["$ref"].split("/")[-1]
        target = defs[name]
        if is_u64_decimal(target):
            return "string"
        if name == "NullableString":
            return "string | null"
        if name == "EpochMillis":
            return "number"
        return name
    if "anyOf" in schema:
        return " | ".join(ts_type(item, defs) for item in schema["anyOf"])
    if schema.get("enum") and schema.get("type") == "string":
        return " | ".join(json.dumps(v) for v in schema["enum"])
    if "const" in schema:
        return json.dumps(schema["const"])
    types = schema.get("type")
    if types == "string":
        return "string"
    if types == "boolean":
        return "boolean"
    if types == "integer" or types == "number":
        return "number"
    if types == "array":
        return f"Array<{ts_type(schema.get('items', {}), defs)}>"
    if types == ["string", "null"]:
        return "string | null"
    if types == "null":
        return "null"
    if types == "object":
        return "ContextValue"
    return "unknown"


def object_fields(schema: dict) -> tuple[list[str], dict]:
    required = list(schema.get("required", []))
    return required, schema.get("properties", {})


def emit_rust(schema: dict) -> str:
    defs = schema["$defs"]
    catalog = schema["x-vodoge-message-catalog"]
    kinds = defs["MessageKind"]["enum"]
    lines = [
        "// Code generated by packages/contract/codegen/generate.py. DO NOT EDIT.",
        "#![allow(clippy::derivable_impls)]",
        "",
        "use std::collections::BTreeMap;",
        "",
        "use serde::{Deserialize, Deserializer, Serialize, Serializer};",
        "",
        f"pub const PROTOCOL_VERSION: u8 = {schema['$defs']['Envelope']['properties']['v']['const']};",
        f"pub const SCHEMA_ID: &str = {json.dumps(schema['$id'])};",
        f"pub const WS_SUBPROTOCOL: &str = {json.dumps(schema['x-vodoge-contract']['wire']['websocket_subprotocol'])};",
        "",
        "#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]",
        "pub enum MessageKind {",
    ]
    for kind in kinds:
        lines.append(f"    {kind},")
    lines += [
        "}",
        "",
        "impl MessageKind {",
        "    pub fn as_str(self) -> &'static str {",
        "        match self {",
    ]
    for kind in kinds:
        lines.append(f'            Self::{kind} => "{kind}",')
    lines += [
        "        }",
        "    }",
        "",
        "    pub fn is_sequenced(self) -> bool {",
        "        match self {",
    ]
    for kind in kinds:
        sequenced = catalog[kind]["sequenced"]
        lines.append(f"            Self::{kind} => {str(sequenced).lower()},")
    lines += [
        "        }",
        "    }",
        "}",
        "",
        "#[derive(Clone, Debug, Serialize, Deserialize)]",
        "#[serde(untagged)]",
        "pub enum ContextValue {",
        "    Null,",
        "    Bool(bool),",
        "    Number(f64),",
        "    String(String),",
        "    Array(Vec<ContextValue>),",
        "    Object(BTreeMap<String, ContextValue>),",
        "}",
        "",
        "mod u64_decimal {",
        "    use super::*;",
        "    pub fn serialize<S: Serializer>(value: &u64, serializer: S) -> Result<S::Ok, S::Error> {",
        "        serializer.serialize_str(&value.to_string())",
        "    }",
        "    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u64, D::Error> {",
        "        let raw = String::deserialize(deserializer)?;",
        "        raw.parse::<u64>().map_err(serde::de::Error::custom)",
        "    }",
        "}",
        "",
        "mod opt_u64_decimal {",
        "    use super::*;",
        "    pub fn serialize<S: Serializer>(value: &Option<u64>, serializer: S) -> Result<S::Ok, S::Error> {",
        "        match value {",
        "            Some(v) => serializer.serialize_some(&v.to_string()),",
        "            None => serializer.serialize_none(),",
        "        }",
        "    }",
        "    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Option<u64>, D::Error> {",
        "        let raw = Option::<String>::deserialize(deserializer)?;",
        "        raw.map(|value| value.parse::<u64>().map_err(serde::de::Error::custom)).transpose()",
        "    }",
        "}",
        "",
    ]

    skip = {
        "Envelope",
        "MessageKind",
        "Uuid",
        "EpochMillis",
        "SequenceNumber",
        "SequenceCursor",
        "Iccid",
        "Imei",
        "Sha256",
        "HttpsUrl",
        "NullableString",
        "ContextValue",
        "Command",
    }

    for name, definition in defs.items():
        if name in skip:
            continue
        if definition.get("enum") and definition.get("type") == "string" and "properties" not in definition:
            continue
        if definition.get("oneOf"):
            continue
        if definition.get("type") != "object":
            continue
        required, properties = object_fields(definition)
        lines.append("#[derive(Clone, Debug, Serialize, Deserialize)]")
        if definition.get("additionalProperties") is False:
            lines.append("#[serde(deny_unknown_fields)]")
        lines.append(f"pub struct {name} {{")
        for field, spec in properties.items():
            rust_field = rust_ident(field)
            ty = rust_type(spec, defs)
            optional = field not in required and not ty.startswith("Option<")
            if optional:
                ty = f"Option<{ty}>"
            attrs = [f'rename = "{field}"']
            resolved = spec
            if "$ref" in spec:
                resolved = defs[spec["$ref"].split("/")[-1]]
            if is_u64_decimal(spec) or is_u64_decimal(resolved):
                if ty.startswith("Option<"):
                    attrs.append("default")
                    attrs.append('skip_serializing_if = "Option::is_none"')
                    attrs.append('with = "opt_u64_decimal"')
                else:
                    attrs.append('with = "u64_decimal"')
            elif ty.startswith("Option<"):
                attrs.append("default")
                attrs.append('skip_serializing_if = "Option::is_none"')
            lines.append(f"    #[serde({', '.join(attrs)})]")
            lines.append(f"    pub {rust_field}: {ty},")
        lines.append("}")
        lines.append("")

    # Command internally tagged enum
    lines += [
        "#[derive(Clone, Debug, Serialize, Deserialize)]",
        '#[serde(tag = "kind", deny_unknown_fields)]',
        "pub enum Command {",
    ]
    for variant in defs["Command"]["oneOf"]:
        vname = variant["$ref"].split("/")[-1]
        vdef = defs[vname]
        fields = []
        for field, spec in vdef.get("properties", {}).items():
            if field == "kind":
                continue
            ty = rust_type(spec, defs)
            if field not in vdef.get("required", []) and not ty.startswith("Option<"):
                ty = f"Option<{ty}>"
            fields.append((field, ty))
        kind_const = vdef["properties"]["kind"]["const"]
        if fields:
            lines.append(f"    {kind_const} {{")
            for field, ty in fields:
                lines.append(f'        #[serde(rename = "{field}")]')
                if ty.startswith("Option<"):
                    lines.append('        #[serde(default, skip_serializing_if = "Option::is_none")]')
                lines.append(f"        {rust_ident(field)}: {ty},")
            lines.append("    },")
        else:
            lines.append(f"    {kind_const},")
    lines += ["}", ""]

    lines += [
        "#[derive(Clone, Debug, Serialize, Deserialize)]",
        "#[serde(deny_unknown_fields)]",
        "pub struct Envelope {",
        '    pub v: u8,',
        "    pub kind: MessageKind,",
        "    pub id: String,",
        "    pub ts: i64,",
        '    #[serde(rename = "device_id")]',
        "    pub device_id: String,",
        '    #[serde(default, skip_serializing_if = "Option::is_none", with = "opt_u64_decimal")]',
        "    pub seq: Option<u64>,",
        '    #[serde(default, skip_serializing_if = "Option::is_none", rename = "trace_id")]',
        "    pub trace_id: Option<String>,",
        "    pub payload: serde_json::Value,",
        "}",
        "",
        "impl Envelope {",
        "    pub fn validate_sequence(&self) -> Result<(), String> {",
        "        match (self.kind.is_sequenced(), self.seq) {",
        '            (true, None) => Err(format!("{} requires seq", self.kind.as_str())),',
        '            (false, Some(_)) => Err(format!("{} must not have seq", self.kind.as_str())),',
        "            _ => Ok(()),",
        "        }",
        "    }",
        "}",
        "",
    ]
    return "\n".join(lines)


def emit_go(schema: dict) -> str:
    defs = schema["$defs"]
    catalog = schema["x-vodoge-message-catalog"]
    kinds = defs["MessageKind"]["enum"]
    lines = [
        "// Code generated by packages/contract/codegen/generate.py. DO NOT EDIT.",
        "",
        "package contract",
        "",
        'import "encoding/json"',
        "",
        f"const ProtocolVersion = {schema['$defs']['Envelope']['properties']['v']['const']}",
        f"const SchemaID = {json.dumps(schema['$id'])}",
        f"const WebSocketSubprotocol = {json.dumps(schema['x-vodoge-contract']['wire']['websocket_subprotocol'])}",
        "",
        "type MessageKind string",
        "",
        "const (",
    ]
    for kind in kinds:
        lines.append(f'\tMessageKind{kind} MessageKind = "{kind}"')
    lines += [
        ")",
        "",
        "func (kind MessageKind) Sequenced() bool {",
        "	switch kind {",
    ]
    sequenced = [k for k, meta in catalog.items() if meta["sequenced"]]
    lines.append("\tcase " + ", ".join(f"MessageKind{k}" for k in sequenced) + ":")
    lines += [
        "		return true",
        "	default:",
        "		return false",
        "	}",
        "}",
        "",
        "type Envelope struct {",
        '\tV        int             `json:"v"`',
        '\tKind     MessageKind     `json:"kind"`',
        '\tID       string          `json:"id"`',
        '\tTs       int64           `json:"ts"`',
        '\tDeviceID string          `json:"device_id"`',
        '\tSeq      *string         `json:"seq,omitempty"`',
        '\tTraceID  *string         `json:"trace_id,omitempty"`',
        '\tPayload  json.RawMessage `json:"payload"`',
        "}",
        "",
    ]

    skip = {
        "Envelope",
        "MessageKind",
        "Uuid",
        "EpochMillis",
        "SequenceNumber",
        "SequenceCursor",
        "Iccid",
        "Imei",
        "Sha256",
        "HttpsUrl",
        "NullableString",
        "ContextValue",
        "Command",
    }
    for name, definition in defs.items():
        if name in skip or definition.get("type") != "object" or definition.get("oneOf"):
            continue
        required, properties = object_fields(definition)
        lines.append(f"type {name} struct {{")
        for field, spec in properties.items():
            ty = go_type(spec, defs)
            if field not in required and not ty.startswith("*") and not ty.startswith("[]"):
                if ty in {"string", "int64", "uint64", "bool", "float64"}:
                    ty = "*" + ty
            tag = f'`json:"{field}'
            if field not in required:
                tag += ",omitempty"
            tag += '"`'
            lines.append(f"\t{go_ident(field)} {ty} {tag}")
        lines.append("}")
        lines.append("")

    lines += [
        "type Command json.RawMessage",
        "",
    ]
    return "\n".join(lines)


def emit_ts(schema: dict) -> str:
    defs = schema["$defs"]
    catalog = schema["x-vodoge-message-catalog"]
    kinds = defs["MessageKind"]["enum"]
    lines = [
        "/* Code generated by packages/contract/codegen/generate.py. DO NOT EDIT. */",
        "",
        f"export const PROTOCOL_VERSION = {schema['$defs']['Envelope']['properties']['v']['const']} as const;",
        f"export const SCHEMA_ID = {json.dumps(schema['$id'])} as const;",
        f"export const WS_SUBPROTOCOL = {json.dumps(schema['x-vodoge-contract']['wire']['websocket_subprotocol'])} as const;",
        "",
        "export type Uuid = string;",
        "export type Iccid = string;",
        "export type Imei = string;",
        "export type Sha256 = string;",
        "export type HttpsUrl = string;",
        "export type EpochMillis = number;",
        "export type SequenceNumber = string;",
        "export type SequenceCursor = string;",
        "",
        "export type MessageKind =",
    ]
    for i, kind in enumerate(kinds):
        suffix = " |" if i != len(kinds) - 1 else ";"
        lines.append(f"  | {json.dumps(kind)}{suffix}")
    lines += [
        "",
        "export const SEQUENCED_KINDS: ReadonlySet<MessageKind> = new Set([",
    ]
    for kind, meta in catalog.items():
        if meta["sequenced"]:
            lines.append(f"  {json.dumps(kind)},")
    lines += [
        "]);",
        "",
        "export type ContextValue =",
        "  | null",
        "  | boolean",
        "  | number",
        "  | string",
        "  | ContextValue[]",
        "  | { [key: string]: ContextValue };",
        "",
        "export interface Envelope {",
        "  v: 1;",
        "  kind: MessageKind;",
        "  id: Uuid;",
        "  ts: EpochMillis;",
        "  device_id: Uuid;",
        "  seq?: SequenceNumber;",
        "  trace_id?: Uuid;",
        "  payload: unknown;",
        "}",
        "",
    ]

    skip = {
        "Envelope",
        "MessageKind",
        "Uuid",
        "EpochMillis",
        "SequenceNumber",
        "SequenceCursor",
        "Iccid",
        "Imei",
        "Sha256",
        "HttpsUrl",
        "NullableString",
        "ContextValue",
        "Command",
    }
    for name, definition in defs.items():
        if name in skip or definition.get("type") != "object" or definition.get("oneOf"):
            continue
        required, properties = object_fields(definition)
        lines.append(f"export interface {name} {{")
        for field, spec in properties.items():
            optional = "?" if field not in required else ""
            lines.append(f"  {ts_ident(field)}{optional}: {ts_type(spec, defs)};")
        lines.append("}")
        lines.append("")

    lines.append("export type Command =")
    variants = []
    for variant in defs["Command"]["oneOf"]:
        variants.append(variant["$ref"].split("/")[-1])
    for i, name in enumerate(variants):
        suffix = " |" if i != len(variants) - 1 else ";"
        lines.append(f"  | {name}{suffix}")
    lines.append("")
    return "\n".join(lines)


def gofmt(content: str) -> str:
    try:
        proc = subprocess.run(
            ["gofmt"],
            input=content.encode("utf-8"),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
    except FileNotFoundError:
        return content
    if proc.returncode != 0:
        return content
    formatted = proc.stdout.decode("utf-8")
    return formatted or content


def write_if_changed(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not content.endswith("\n"):
        content += "\n"
    existing = path.read_text(encoding="utf-8") if path.exists() else None
    if existing != content:
        path.write_text(content, encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--schema", type=Path, default=DEFAULT_SCHEMA)
    parser.add_argument("--rust", type=Path)
    parser.add_argument("--go", type=Path)
    parser.add_argument("--ts", type=Path)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()

    schema = load_schema(args.schema)
    rust = emit_rust(schema)
    go = gofmt(emit_go(schema))
    ts = emit_ts(schema)

    targets = []
    if args.rust:
        targets.append((args.rust, rust))
    if args.go:
        targets.append((args.go, go))
    if args.ts:
        targets.append((args.ts, ts))
    if not targets:
        targets = [
            (ROOT / "go" / "contract.go", go),
            (ROOT / "ts" / "index.ts", ts),
        ]

    failed = False
    for path, content in targets:
        if not content.endswith("\n"):
            content += "\n"
        if args.check:
            current = path.read_text(encoding="utf-8") if path.exists() else ""
            if current != content:
                print(f"generated contract is stale: {path}", file=sys.stderr)
                failed = True
        else:
            write_if_changed(path, content)

    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
