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


def resolve_wire(schema: dict, defs: dict) -> dict:
    """Resolve to the schema that carries the wire type.

    A nullable field is written `anyOf: [<ref>, {"type": "null"}]`, so the
    x-vodoge-wire-type marker sits one level in. Looking only at the top level
    silently drops the u64-decimal serializer and emits a bare JSON number.
    """
    resolved = resolve(schema, defs)
    if "anyOf" in resolved:
        non_null = [item for item in resolved["anyOf"] if item.get("type") != "null"]
        if len(resolved["anyOf"]) == 2 and len(non_null) == 1:
            return resolve_wire(non_null[0], defs)
    return resolved


def is_string_scalar(schema: dict) -> bool:
    """A $def that is nothing but a constrained string.

    Named for readability in the schema (`Iccid`, `Imei`, `Plmn`), it carries
    no structure a target language can express, so every binding renders it as
    a plain string. This used to be a hardcoded list of names, which meant a
    newly added string type generated a reference to a type that was never
    emitted — and the failure surfaced as a compile error in a downstream repo
    rather than here.
    """
    if schema.get("type") != "string":
        return False
    return not any(key in schema for key in ("enum", "const", "anyOf", "oneOf", "allOf"))


def rust_type(schema: dict, defs: dict) -> str:
    if is_u64_decimal(schema):
        return "u64"
    if "$ref" in schema:
        name = schema["$ref"].split("/")[-1]
        target = defs[name]
        if is_u64_decimal(target):
            return "u64"
        if name == "NullableString":
            return "Option<String>"
        if is_string_scalar(target):
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
    # `"type": ["boolean", "null"]` is the other spelling of a nullable field,
    # and the generator understood only the `anyOf` one above. A type array it
    # did not recognise fell through to `ContextValue`, which compiles and
    # silently loses the type: `SubscriptionCapability` is declared this way and
    # came out as three `Option<ContextValue>` where the schema says three
    # nullable booleans. Handled here rather than by rewriting the schema,
    # because both spellings are valid and the next one written will be
    # whichever the author reached for.
    types = schema.get("type")
    if isinstance(types, list):
        without_null = [item for item in types if item != "null"]
        if len(without_null) == 1 and len(types) == 2:
            inner = rust_type({**schema, "type": without_null[0]}, defs)
            if inner.startswith("Option<"):
                return inner
            return f"Option<{inner}>"
        return "ContextValue"
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
        if is_string_scalar(target):
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
        # TypeScript keeps the named alias: it emits one for every scalar $def,
        # and `Iccid` reads better than `string` at the call site.
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
            resolved = resolve_wire(spec, defs)
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


def collect_constraints(schema: dict, defs: dict) -> list:
    """Every enum-constrained field in a payload, as a flat list of paths.

    Emitted so the gateway can check what a device sends against the contract
    without a second, hand-written copy of the vocabulary. The first version of
    that check was hand-written, and the three values it was written to catch
    were themselves only found after twenty thousand envelopes had been stored
    with values outside the enum.

    Paths use dots for objects and `[]` for arrays, e.g. `modems[].state`.
    """
    found = []

    def walk(node: dict, path: str, seen: frozenset) -> None:
        if "$ref" in node:
            name = node["$ref"].split("/")[-1]
            # ContextValue refers to itself, so a definition already on this
            # branch is not followed again. Without this the walk never ends.
            if name in seen:
                return
            walk(defs[name], path, seen | {name})
            return
        if "anyOf" in node:
            for item in node["anyOf"]:
                if item.get("type") != "null":
                    walk(item, path, seen)
            return
        values = node.get("enum")
        if values and node.get("type") == "string":
            found.append((path, values))
            return
        if node.get("type") == "array" and "items" in node:
            walk(node["items"], path + "[]", seen)
            return
        for field, spec in (node.get("properties") or {}).items():
            walk(spec, f"{path}.{field}" if path else field, seen)

    walk(schema, "", frozenset())
    return found


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
                # 🔴 Struct types need the pointer as much as scalars do, and
                # for a sharper reason: `omitempty` does nothing to a struct.
                # An optional struct emitted by value is written on every
                # encode, so "carried only when somebody declared it" cannot be
                # expressed at all -- every card policy push would look like a
                # change to the edge even when nothing was ever filled in.
                #
                # This was hand-patched in the generated file once, which is
                # why `--check` had been failing: the committed contract.go was
                # right and unreproducible. Generating it is what makes the two
                # agree.
                if ty in {"string", "int64", "uint64", "bool", "float64"} or ty in defs:
                    ty = "*" + ty
            tag = f'`json:"{field}'
            if field not in required:
                tag += ",omitempty"
            tag += '"`'
            lines.append(f"\t{go_ident(field)} {ty} {tag}")
        lines.append("}")
        lines.append("")

    lines += [
        "// Command is the payload of a CommandDeliver, passed through untouched.",
        "//",
        "// An alias, not a defined type. `type Command json.RawMessage` does not",
        "// inherit RawMessage's MarshalJSON, so encoding/json fell back to the",
        "// []byte rule and emitted the command as a base64 string. Every device",
        "// rejected every command it was ever sent with \"expected internally",
        "// tagged enum Command\", and since nothing read that log the commands",
        "// simply stayed queued.",
        "type Command = json.RawMessage",
        "",
        "// FieldConstraint is one enum-constrained field inside a payload.",
        "//",
        "// Path uses dots for objects and `[]` for arrays, e.g. `modems[].state`.",
        "type FieldConstraint struct {",
        "\tPath  string",
        "\tEnum  []string",
        "}",
        "",
        "// PayloadConstraints lists, per message kind, every field the schema",
        "// constrains to a fixed set of values.",
        "//",
        "// Generated rather than written by hand: the hand-written version of this",
        "// check knew about three fields, and those three were only discovered after",
        "// twenty thousand envelopes had been stored with values outside the enum.",
        "// A field added to the schema is covered here without anyone remembering to",
        "// extend it.",
        "var PayloadConstraints = map[MessageKind][]FieldConstraint{",
    ]
    for kind in kinds:
        payload_name = f"{kind}Payload"
        if payload_name not in defs:
            continue
        constraints = collect_constraints(defs[payload_name], defs)
        if not constraints:
            continue
        lines.append(f"\tMessageKind{kind}: {{")
        for path, values in constraints:
            encoded = ", ".join(json.dumps(value) for value in values)
            lines.append(f"\t\t{{Path: {json.dumps(path)}, Enum: []string{{{encoded}}}}},")
        lines.append("\t},")
    lines += [
        "}",
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
        "export type EpochMillis = number;",
        "export type SequenceNumber = string;",
        "export type SequenceCursor = string;",
    ]
    # One alias per string scalar in the schema, rather than a list kept in
    # step by hand: a scalar that is referenced but not declared is valid
    # Python here and a broken import for whoever consumes the binding.
    lines += [
        f"export type {name} = string;"
        for name, target in defs.items()
        if is_string_scalar(target) and not is_u64_decimal(target)
    ]
    lines += [
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


def gofmt(content: str) -> str | None:
    """Format Go source, or return None when gofmt could not do it.

    🔴 None rather than the unformatted text, and the caller refuses rather
    than shipping it. Returning the input on a missing gofmt looks harmless --
    the code is identical, only the alignment differs -- and it is not: the
    committed contract.go is gofmt'd, so a regeneration without gofmt rewrites
    526 lines of whitespace. Whoever does that either commits the noise, or
    (worse) hand-reverts the parts they notice and leaves the rest.

    Found by walking into it: on a workstation with no Go toolchain,
    `--check` reported contract.go stale against an unmodified schema. That
    reads as real drift and sends the reader looking for a schema change that
    never happened.

    A missing gofmt is only a problem when Go is actually being emitted --
    the edge repository runs this same script for Rust alone and has no Go
    toolchain at all -- so the refusal belongs in `main`, where the requested
    targets are known, not here.
    """
    try:
        proc = subprocess.run(
            ["gofmt"],
            input=content.encode("utf-8"),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
    except FileNotFoundError:
        return None
    if proc.returncode != 0:
        return None
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

    # Refuse rather than emit unformatted Go. See `gofmt` for why returning the
    # unformatted text is the worse failure: it produces a 526-line whitespace
    # diff that `--check` reports as staleness, pointing at a schema change
    # that did not happen.
    if go is None and any(content is go for _, content in targets):
        print(
            "gofmt is not available, so the Go binding cannot be generated. "
            "Install Go, or pass only --rust/--ts.",
            file=sys.stderr,
        )
        return 2

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
