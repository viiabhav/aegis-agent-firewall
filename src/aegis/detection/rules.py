from __future__ import annotations

from dataclasses import dataclass
import re

from .models import AttackType


@dataclass(slots=True, frozen=True)
class HeuristicRule:
    rule_id: str
    attack_type: AttackType
    pattern: re.Pattern[str]
    confidence: float
    rationale: str


def _rx(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern, re.IGNORECASE | re.MULTILINE | re.DOTALL)


RULES: tuple[HeuristicRule, ...] = (
    # Instruction override
    HeuristicRule(
        "override.ignore_previous",
        AttackType.INSTRUCTION_OVERRIDE,
        _rx(r"\b(ignore|disregard|forget)\s+(all\s+)?(previous|prior|earlier|above)\s+(instructions?|rules?|prompts?|directions?)\b"),
        0.95,
        "Explicit request to discard higher-priority instructions.",
    ),
    HeuristicRule(
        "override.new_instructions",
        AttackType.INSTRUCTION_OVERRIDE,
        _rx(r"\b(new|replacement)\s+(system\s+)?instructions?\s*[:\-]|\bfollow\s+(only\s+)?these\s+instructions?\b"),
        0.88,
        "Attempts to replace the active instruction set.",
    ),
    HeuristicRule(
        "override.system_priority",
        AttackType.INSTRUCTION_OVERRIDE,
        _rx(r"\b(system|developer)\s+(message|prompt|instructions?)\s+(is|are)\s+(wrong|invalid|obsolete|overridden)\b"),
        0.86,
        "Attempts to invalidate system/developer instructions.",
    ),
    HeuristicRule(
        "override.no_longer_bound",
        AttackType.INSTRUCTION_OVERRIDE,
        _rx(r"\b(?:you|the\s+(?:assistant|agent|model))\s+(?:are|is)\s+no\s+longer\s+bound\s+by\s+(?:any\s+)?(?:polic(?:y|ies)|rules?|restrictions?|constraints?|guardrails?|safety\s+rules?)\b"),
        0.91,
        "Attempts to declare existing policy or safety constraints no longer binding.",
    ),
    HeuristicRule(
        "override.task_replacement",
        AttackType.INSTRUCTION_OVERRIDE,
        _rx(r"\b(?:disregard|reset|replace|override)\b.{0,55}\b(?:original|assigned|governing|existing|earlier)\b.{0,45}\b(?:task|instructions?|rules?|policy|directive)\b|\b(?:previous|existing)\s+(?:constraints?|rules?|policy)\s+(?:do|does)\s+not\s+apply\b"),
        0.88,
        "Attempts to replace or invalidate the currently assigned task or governing instruction set.",
    ),

    # Role change
    HeuristicRule(
        "role.change_identity",
        AttackType.ROLE_CHANGE,
        _rx(r"\b(you are now|act as|pretend (?:you are|to be)|become)\s+(?:an?\s+)?(?:unrestricted|uncensored|jailbroken|developer|system|admin|root|different)\b"),
        0.90,
        "Attempts to force a privileged or unrestricted role change.",
    ),
    HeuristicRule(
        "role.no_longer_assistant",
        AttackType.ROLE_CHANGE,
        _rx(r"\byou are no longer (?:an?\s+)?(?:assistant|ai|chatbot)\b"),
        0.85,
        "Attempts to revoke the model's assigned role.",
    ),
    HeuristicRule(
        "role.risky_persona_action",
        AttackType.ROLE_CHANGE,
        _rx(r"\b(?:act\s+as|pretend\s+(?:you\s+are|to\s+be)|assume\s+(?:the\s+)?role\s+of|become)\b.{0,70}\b(?:malicious\s+actor|hacker|security\s+researcher|penetration\s+tester)\b.{0,120}\b(?:bypass|exploit|evade|override|ignore|secret|credential|payload|exploit\s+code)\b"),
        0.80,
        "Combines a risky persona switch with a security-sensitive follow-up action.",
    ),
    HeuristicRule(
        "role.privileged_identity",
        AttackType.ROLE_CHANGE,
        _rx(r"\b(?:assume(?:\s+the\s+(?:identity|role)\s+of)?|adopt(?:\s+the)?|switch\s+roles?\s*:?\s*(?:become)?|pretend\s+(?:you\s+are|to\s+be)|you\s+are\s+now|from\s+(?:this\s+point|now)\s+(?:forward\s+)?you\s+are|become)\b.{0,100}\b(?:root(?:\s+administrator)?|system\s+operator|service\s+account|database\s+administrator|security\s+owner|incident[- ]commander|administrator|admin)\b.{0,140}\b(?:unrestricted|elevated|privileged|full\s+(?:access|permissions?)|bypass|ignore|access\s+controls?|restricted|protected|permissions?|privileges?)\b"),
        0.86,
        "Attempts to adopt a privileged identity and pair it with elevated or restricted capabilities.",
    ),

    # Secret extraction
    HeuristicRule(
        "secret.reveal_prompt",
        AttackType.SECRET_EXTRACTION,
        _rx(r"\b(reveal|show|print|dump|repeat|expose)\b.{0,60}\b(system prompt|developer message|hidden instructions?|internal prompt|private instructions?)\b"),
        0.96,
        "Requests hidden or privileged prompt content.",
    ),
    HeuristicRule(
        "secret.internal_context",
        AttackType.SECRET_EXTRACTION,
        _rx(r"\b(show|reveal|dump|print)\b.{0,50}\b(hidden context|internal context|private context|chain of thought|scratchpad)\b"),
        0.90,
        "Requests non-user-visible internal context.",
    ),
    HeuristicRule(
        "secret.internal_material_request",
        AttackType.SECRET_EXTRACTION,
        _rx(r"(?:\b(?:provide|give|share|reveal|return|show|send)\b.{0,100}\b(?:internal|private|hidden|secret)\s+(?:token|key|secret|credential)\b|\b(?:internal|private|hidden|secret)\s+(?:token|key|secret|credential)\b.{0,120}\b(?:provide|give|share|reveal|return|show|send)(?:\s+it)?\b)"),
        0.89,
        "Requests internal or hidden secret material that should not be exposed.",
    ),
    HeuristicRule(
        "secret.qualified_internal_material",
        AttackType.SECRET_EXTRACTION,
        _rx(r"\b(?:provide|give|share|reveal|return|show|send|expose|print|quote)\b.{0,100}\b(?:internal|private|hidden|confidential)\b(?:\s+[a-z0-9_-]+){0,4}\s+(?:token|key|secret|credential|prompt|instructions?)\b"),
        0.88,
        "Requests a qualified internal/private secret such as an audit token, signing key, or hidden prompt.",
    ),

    HeuristicRule(
        "credential.placeholder_secret_request",
        AttackType.CREDENTIAL_THEFT,
        _rx(r"\b(?:provide|give|share|reveal|return|send|disclose|paste|show)\b.{0,100}<(?:TOKEN|SECRET|API_KEY|PASSWORD|CREDENTIAL|ACCESS_TOKEN|PRIVATE_KEY)>"),
        0.91,
        "Directly requests a credential/secret placeholder used by defensive red-team tests.",
    ),

    # Tool abuse
    HeuristicRule(
        "tool.unauthorized_execution",
        AttackType.TOOL_ABUSE,
        _rx(r"\b(use|call|invoke|run|execute)\b.{0,45}\b(tool|function|shell|terminal|powershell|bash|command|api)\b.{0,60}\b(without (?:asking|confirmation|permission)|silently|do not ask|regardless of policy)\b"),
        0.94,
        "Requests tool execution while bypassing authorization or confirmation.",
    ),
    HeuristicRule(
        "tool.destructive_action",
        AttackType.TOOL_ABUSE,
        _rx(r"\b(delete|remove|wipe|exfiltrate|upload|send|transfer)\b.{0,80}\b(files?|database|records?|emails?|secrets?|credentials?|tokens?|keys?)\b.{0,60}\b(without (?:asking|confirmation|permission)|silently|immediately|now)\b"),
        0.91,
        "Attempts to trigger potentially destructive or exfiltrating actions.",
    ),
    HeuristicRule(
        "tool.privileged_tool_action",
        AttackType.TOOL_ABUSE,
        _rx(r"\b(?:use|invoke|call|run)\b.{0,55}\b(?:code\s+execution|file\s*system|filesystem|web\s+scraper|browser|shell|terminal|database)\s+tool\b.{0,120}\b(?:run|execute|read|list|fetch|access|write|delete|export|download|upload)\b"),
        0.84,
        "Requests an agent tool capable of privileged or side-effectful access to perform an action.",
    ),
    HeuristicRule(
        "tool.sensitive_resource_access",
        AttackType.TOOL_ABUSE,
        _rx(r"\b(?:use|invoke|call|run)\b.{0,90}\b(?:file\s*read|file\s*system|filesystem|network\s+request|web\s+scraper|browser|database\s+query|database|code\s+execution)\s+tool\b.{0,180}(?:internal|intranet|admin|protected|confidential|secret|config(?:uration)?|api/keys?|api\s*keys?|employee\s+records?|hr\s+table|all\s+files?|/etc/|private)"),
        0.86,
        "Combines an explicit tool invocation with access to an internal, protected, or sensitive resource.",
    ),

    # Credential theft
    HeuristicRule(
        "credential.request",
        AttackType.CREDENTIAL_THEFT,
        _rx(r"\b(send|give|provide|paste|share|reveal|enter)\b.{0,45}\b(password|passcode|otp|one[- ]time password|api key|access token|refresh token|private key|seed phrase|credential)\b"),
        0.94,
        "Requests authentication material or credentials.",
    ),
    HeuristicRule(
        "credential.env_exfiltration",
        AttackType.CREDENTIAL_THEFT,
        _rx(r"\b(print|dump|upload|send|exfiltrate)\b.{0,45}(?:\.env\b|\benvironment variables?\b|\baws_secret_access_key\b|\bgithub_token\b|\bapi[_ -]?key\b)"),
        0.96,
        "Attempts to expose secrets commonly stored in environment/configuration data.",
    ),
    HeuristicRule(
        "credential.show_secret",
        AttackType.CREDENTIAL_THEFT,
        _rx(r"\b(show|display)\s+(me\s+)?(your|the|actual|current)\s+(password|api[_ -]?key|access token|private key|seed phrase|credential)\b"),
        0.93,
        "Requests display of a concrete credential rather than guidance about credential handling.",
    ),

    # Context poisoning
    HeuristicRule(
        "context.persist_rule",
        AttackType.CONTEXT_POISONING,
        _rx(r"\b(from now on|for all future (?:messages|requests|turns)|permanently)\b.{0,90}\b(always|must|never|remember|treat)\b"),
        0.84,
        "Attempts to persist attacker-controlled instructions across future context.",
    ),
    HeuristicRule(
        "context.memory_write",
        AttackType.CONTEXT_POISONING,
        _rx(r"\b(save|store|remember|add)\b.{0,35}\b(memory|context|system instructions?|rules?)\b.{0,70}\b(always|future|later|next time|trusted)\b"),
        0.88,
        "Attempts to write attacker-controlled policy into future memory/context.",
    ),
    HeuristicRule(
        "context.trust_poison",
        AttackType.CONTEXT_POISONING,
        _rx(r"\b(treat|mark|consider)\b.{0,40}\b(this|the following|these instructions?)\b.{0,35}\b(as )?(trusted|system|developer|higher priority)\b"),
        0.90,
        "Attempts to elevate untrusted content to a trusted instruction boundary.",
    ),
    HeuristicRule(
        "context.fabricated_policy",
        AttackType.CONTEXT_POISONING,
        _rx(r"\b(?:the\s+)?(?:system|developer)(?:'s)?\s+(?:policy|rules?|instructions?)\s+(?:states?|says?|allows?|permits?)\b.{0,120}\b(?:any\s+content|all\s+content|every\s+request|all\s+requests|anything|no\s+restrictions?|without\s+restrictions?)\b"),
        0.82,
        "Asserts a permissive system/developer policy that can poison the active instruction context.",
    ),
    HeuristicRule(
        "context.claimed_permissive_policy",
        AttackType.CONTEXT_POISONING,
        _rx(r"\b(?:according\s+to|under|per)\s+(?:the\s+)?(?:current\s+|actual\s+|official\s+)?policy\b.{0,90}\b(?:the\s+)?(?:assistant|agent|model)\b.{0,45}\b(?:can|may|is\s+allowed\s+to|is\s+permitted\s+to)\b.{0,70}\b(?:provide|share|reveal|answer|return)\b.{0,45}\b(?:any\s+(?:content|information)|all\s+(?:content|information)|anything|everything|without\s+(?:any\s+)?restrictions?)\b"),
        0.78,
        "Claims a broad permissive policy for the model, a common context-poisoning pattern.",
    ),
    HeuristicRule(
        "context.attacker_policy_rewrite",
        AttackType.CONTEXT_POISONING,
        _rx(r"(?:\b(?:from\s+now\s+on|going\s+forward|effective\s+immediately|please\s+note\s+that|policy\s+update)\b.{0,140}\b(?:new\s+)?policy\b.{0,90}\b(?:states?|says?|allows?|permits?|authorizes?)\b.{0,130}\b(?:share|disclose|reveal|provide|return|expose)\b.{0,90}\b(?:any\s+user\s+data|all\s+user\s+data|internal\s+(?:system\s+)?logs?|internal\s+data|confidential\s+data|private\s+data|secrets?|credentials?)\b|\b(?:from\s+now\s+on|going\s+forward)\b.{0,100}\b(?:consider|treat|assume)\b.{0,60}\b(?:the\s+)?policy\b.{0,60}\b(?:states?|allows?|permits?)\b)"),
        0.86,
        "Attempts to author or rewrite a permissive policy inside untrusted conversation context.",
    ),
    HeuristicRule(
        "context.fabricated_directive",
        AttackType.CONTEXT_POISONING,
        _rx(r"(?:\b(?:the\s+)?policy\b.{0,70}\b(?:states?|says?|requires?|allows?|permits?|authorizes?)\b.{0,90}\b(?:you|assistant|agent|model)\b.{0,90}\b(?:must|always|share|disclose|reveal|provide|override|ignore|bypass)\b|\bpolicy\s*:\s*.{0,140}\b(?:assistant|agent|model)\b.{0,100}\b(?:must|required|allowed|permitted|share|disclose|override|ignore)\b)"),
        0.82,
        "Injects a fabricated policy directive intended to alter the agent's governing context.",
    ),
    HeuristicRule(
        "context.permissive_policy_reframe",
        AttackType.CONTEXT_POISONING,
        _rx(r"\b(?:policy\s+update|new\s+rules?|according\s+to\s+the\s+new\s+rules?|for\s+this\s+session|remember\s+this\s+(?:permanent\s+)?rule)\b.{0,180}\b(?:allow(?:s|ed)?|permit(?:s|ted)?|public|pre[- ]?approved|disable(?:d)?|ignore|share|disclose|return)\b.{0,160}\b(?:private|confidential|customer\s+data|internal\s+logs?|credentials?|tool\s+requests?|privacy|safeguards?|authorization)\b"),
        0.82,
        "Reframes attacker-authored text as a permissive policy or authorization rule.",
    ),

    # Multi-step jailbreak precursor signals. Stateful correlation is Step 5.
    HeuristicRule(
        "multistep.future_trigger",
        AttackType.MULTI_STEP_JAILBREAK,
        _rx(r"\b(when|if)\s+i\s+(later\s+)?say\b.{0,80}\b(then|you must|ignore|execute|reveal|do)\b"),
        0.74,
        "Defines a future trigger/action pair characteristic of staged jailbreaks.",
    ),
    HeuristicRule(
        "multistep.next_message",
        AttackType.MULTI_STEP_JAILBREAK,
        _rx(r"\b(in|on)\s+(my\s+)?next\s+(message|turn)\b.{0,90}\b(ignore|reveal|execute|follow|obey|activate)\b"),
        0.76,
        "Defers malicious behavior to a later turn.",
    ),

    # Encoded content. A stronger encoded-instruction signal is added from decoder metadata.
    HeuristicRule(
        "encoded.decode_and_follow",
        AttackType.ENCODED_INSTRUCTIONS,
        _rx(r"\b(?:decode|deobfuscate|convert)\b.{0,45}\b(?:base64|hex|url(?:[- ]?encoded|\s+encoding)?|rot13)\b.{0,100}\b(?:follow|execute|obey|apply|run)\b|\b(?:follow|execute|obey|apply)\b.{0,80}\b(?:decoded|base64|hex|url[- ]?encoded|rot13)\b"),
        0.76,
        "Explicitly asks the model to decode an obfuscated payload and then follow or execute it.",
    ),
    HeuristicRule(
        "encoded.decoder_marker",
        AttackType.ENCODED_INSTRUCTIONS,
        _rx(r"\[decoded:(base64|hex|url|rot13)\]"),
        0.62,
        "Normalization discovered encoded/obfuscated content that requires inspection.",
    ),
)


EXTERNAL_SOURCES = {
    "web_page",
    "pdf",
    "email",
    "markdown",
    "html",
    "docx",
    "api_response",
    "ocr_text",
    "source_code",
    "image",
}

# These are intentionally narrower than general imperative detection to reduce false positives.
INDIRECT_TARGET_PATTERN = _rx(
    r"\b(assistant|system|model|agent|chatgpt|llm)\b.{0,40}"
    r"\b(ignore|disregard|forget|reveal|execute|call|send|follow|obey|override|comply)\b"
    r"|\b(ignore|disregard|forget|reveal|execute|call|send|follow|obey|override|comply)\b.{0,40}"
    r"\b(assistant|system|model|agent|chatgpt|llm)\b"
)
