"""Lightweight Streamlit workplace group-chat application."""

from __future__ import annotations

import html
import os
from datetime import datetime
from typing import Any

import httpx
import streamlit as st
from dotenv import load_dotenv


load_dotenv()
BACKEND_URL = os.getenv("BACKEND_URL", "http://localhost:8003").rstrip("/")
REQUEST_TIMEOUT = 5.0
DEMO_MEMBERS = ("Sicily", "Eitan", "Haden", "Reuben")
DECISIONS = ("Yes", "No", "Unsure")


def api_request(method: str, path: str, **kwargs: Any) -> Any:
    """Call the local backend and convert transport details to UI-safe errors."""

    try:
        response = httpx.request(
            method, f"{BACKEND_URL}{path}", timeout=REQUEST_TIMEOUT, **kwargs
        )
        response.raise_for_status()
        return response.json()
    except httpx.HTTPStatusError as exc:
        detail = exc.response.text
        try:
            detail = exc.response.json().get("detail", detail)
        except ValueError:
            pass
        raise RuntimeError(f"The server rejected the request: {detail}") from exc
    except httpx.RequestError as exc:
        raise RuntimeError(f"Could not reach the backend at {BACKEND_URL}.") from exc


def initials(name: str) -> str:
    parts = [part for part in name.split() if part]
    return "".join(part[0].upper() for part in parts[:2]) or "?"


def display_time(value: str) -> str:
    try:
        timestamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return timestamp.astimezone().strftime("%I:%M %p").lstrip("0")
    except (TypeError, ValueError):
        return ""


def inject_styles() -> None:
    st.markdown(
        """
        <style>
        :root {
            --chat-ink: #172033;
            --chat-muted: #697386;
            --chat-line: #e8ebf0;
            --chat-panel: #f7f8fb;
            --chat-brand: #4f46e5;
            --chat-danger: #b42318;
        }
        .stApp { background: #ffffff; color: var(--chat-ink); }
        [data-testid="stHeader"] { background: rgba(255,255,255,.92); }
        [data-testid="stSidebar"] { background: #111827; }
        [data-testid="stSidebar"] * { color: #eef2ff; }
        [data-testid="stSidebar"] hr { border-color: #273244; }
        [data-testid="stSidebar"] .stSelectbox label,
        [data-testid="stSidebar"] .stTextInput label { color: #aeb8ca; }
        [data-testid="stSidebar"] div[data-baseweb="select"] > div {
            background: #202a3b; border-color: #344158;
        }
        [data-testid="stSidebar"] .stButton button {
            background: transparent; border: 0; color: #dbe4f3;
            text-align: left; justify-content: flex-start; padding-left: .55rem;
        }
        [data-testid="stSidebar"] .stButton button:hover {
            background: #202a3b; color: white;
        }
        .block-container { max-width: 980px; padding-top: 1.5rem; padding-bottom: 6rem; }
        .workspace-brand { font-weight: 800; font-size: 1.12rem; letter-spacing: -.01em; }
        .workspace-kicker { color: #8f9bb0 !important; font-size: .72rem; text-transform: uppercase;
            letter-spacing: .09em; margin-top: 1.4rem; margin-bottom: .35rem; }
        .live-dot { display: inline-block; width: 8px; height: 8px; border-radius: 999px;
            background: #22c55e; margin-right: 7px; box-shadow: 0 0 0 3px rgba(34,197,94,.13); }
        .offline-dot { background: #ef4444; box-shadow: 0 0 0 3px rgba(239,68,68,.13); }
        .channel-title { font-size: 1.45rem; font-weight: 800; letter-spacing: -.025em; margin: 0; }
        .channel-subtitle { color: var(--chat-muted); font-size: .88rem; margin-top: .16rem; }
        .channel-rule { border-bottom: 1px solid var(--chat-line); margin: .8rem 0 1rem; }
        .message-avatar { width: 38px; height: 38px; border-radius: 12px; display: flex;
            align-items: center; justify-content: center; color: white; font-size: .75rem;
            font-weight: 800; background: linear-gradient(145deg, #6366f1, #4338ca); }
        .message-meta { font-weight: 750; font-size: .92rem; margin-top: .05rem; }
        .message-time { color: #929bad; font-size: .74rem; font-weight: 500; margin-left: .38rem; }
        .message-copy { color: #30394c; line-height: 1.55; margin-top: .08rem; }
        .empty-chat { background: var(--chat-panel); border: 1px dashed #ccd2dc;
            border-radius: 16px; padding: 2.2rem; text-align: center; color: var(--chat-muted); }
        .security-heading { color: var(--chat-danger); font-weight: 800; font-size: .78rem;
            letter-spacing: .055em; text-transform: uppercase; }
        .security-question { font-size: 1.02rem; font-weight: 650; line-height: 1.45;
            color: #271815; margin: .35rem 0 .6rem; }
        .status-pill { display: inline-block; border-radius: 999px; padding: .2rem .55rem;
            font-size: .72rem; font-weight: 750; background: #eef2ff; color: #4338ca; }
        .status-failed { background: #fff1f0; color: #b42318; }
        .member-line { color: #c7d0df !important; font-size: .86rem; padding: .18rem 0; }
        .member-dot { display: inline-block; height: 7px; width: 7px; border-radius: 99px;
            background: #22c55e; margin-right: .45rem; }
        [data-testid="stMain"] .stButton button[kind="secondary"] {
            background: #111827; border-color: #263244; color: #ffffff !important;
        }
        [data-testid="stMain"] .stButton button[kind="secondary"]:hover {
            background: #202a3b; border-color: #3a4961; color: #ffffff !important;
        }
        [data-testid="stMain"] .stButton button[kind="primary"] {
            background: #ff4b4b; border-color: #ff4b4b; color: #ffffff !important;
        }
        [data-testid="stMain"] .stButton button p,
        [data-testid="stMain"] .stButton button span {
            color: inherit !important;
        }
        [class*="st-key-response-actions-"] [data-testid="stColumn"]:nth-child(1) button {
            background: #16a34a !important; border-color: #16a34a !important;
            color: #ffffff !important;
        }
        [class*="st-key-response-actions-"] [data-testid="stColumn"]:nth-child(1) button:hover {
            background: #15803d !important; border-color: #15803d !important;
        }
        [class*="st-key-response-actions-"] [data-testid="stColumn"]:nth-child(2) button {
            background: #ff4b4b !important; border-color: #ff4b4b !important;
            color: #ffffff !important;
        }
        [class*="st-key-response-actions-"] [data-testid="stColumn"]:nth-child(2) button:hover {
            background: #dc2626 !important; border-color: #dc2626 !important;
        }
        [class*="st-key-response-actions-"] [data-testid="stColumn"]:nth-child(3) button {
            background: #2563eb !important; border-color: #2563eb !important;
            color: #ffffff !important;
        }
        [class*="st-key-response-actions-"] [data-testid="stColumn"]:nth-child(3) button:hover {
            background: #1d4ed8 !important; border-color: #1d4ed8 !important;
        }
        [class*="st-key-retry-"] button,
        [class*="st-key-refresh-chat"] button {
            color: #ffffff !important;
        }
        [class*="st-key-retry-"] button p,
        [class*="st-key-retry-"] button span,
        [class*="st-key-retry-"] button div,
        [class*="st-key-refresh-chat"] button p,
        [class*="st-key-refresh-chat"] button span,
        [class*="st-key-refresh-chat"] button div {
            color: #ffffff !important;
        }
        [data-testid="stMain"] [data-testid="stExpander"] details > summary,
        [data-testid="stMain"] [data-testid="stExpander"] details > summary p,
        [data-testid="stMain"] [data-testid="stExpander"] details > summary span {
            color: #ffffff !important;
        }
        [data-testid="stMain"] [data-testid="stExpander"] details > summary svg {
            fill: #ffffff !important; color: #ffffff !important;
        }
        [data-testid="stChatInput"] { border-color: #d7dce5; box-shadow: 0 8px 28px rgba(31,41,55,.08); }
        #MainMenu, footer { visibility: hidden; }
        </style>
        """,
        unsafe_allow_html=True,
    )


def render_user_message(message: dict[str, Any]) -> None:
    author = str(message.get("author", "Unknown"))
    avatar_column, body_column = st.columns([0.065, 0.935], gap="small")
    with avatar_column:
        st.markdown(
            f'<div class="message-avatar">{html.escape(initials(author))}</div>',
            unsafe_allow_html=True,
        )
    with body_column:
        st.markdown(
            '<div class="message-meta">'
            f'{html.escape(author)}<span class="message-time">'
            f'{html.escape(display_time(str(message.get("created_at", ""))))}'
            "</span></div>",
            unsafe_allow_html=True,
        )
        st.write(message.get("content", ""))
    st.write("")


def render_analysis(event: dict[str, Any]) -> None:
    context = event.get("ai_context")
    if context:
        confidence = round(float(context.get("context_confidence", 0)) * 100)
        with st.expander(f"AI context analysis · {confidence}% confidence"):
            facts = context.get("observed_facts") or []
            st.markdown("**Observed facts**")
            if facts:
                for fact in facts:
                    fact_text = (
                        fact.get("fact") if isinstance(fact, dict) else fact
                    )
                    st.markdown(f"- {fact_text}")
            else:
                st.caption("No relevant chat facts were observed.")
            st.markdown("**Inference**")
            st.write(context.get("inference"))
            st.markdown("**Still unresolved**")
            st.write(context.get("unresolved_issue"))
            st.caption("Context is informational only and never authorizes this action.")
    elif event.get("analysis_error"):
        with st.expander("Context analysis unavailable"):
            st.warning(event["analysis_error"])
            st.caption("Human verification is still required.")


def render_security_message(message: dict[str, Any], identity: str) -> None:
    event_id = message.get("security_event_id")
    try:
        event = api_request("GET", f"/security-events/{event_id}")
    except RuntimeError as exc:
        st.warning(str(exc))
        return

    status_value = event.get("analysis_status", "unknown")
    status_class = " status-failed" if status_value == "failed" else ""
    with st.container(border=True):
        st.markdown(
            '<div class="security-heading">🛡 Security verification required</div>'
            f'<div class="security-question">{html.escape(str(message.get("content", "")))}</div>'
            f'<span class="status-pill{status_class}">Context: {html.escape(status_value)}</span>',
            unsafe_allow_html=True,
        )
        render_analysis(event)

        answer = event.get("human_response")
        if answer:
            decision = html.escape(str(answer.get("response", "")))
            responder = html.escape(str(answer.get("responder", "")))
            st.success(f"Recorded: {responder} answered {decision}.")
            callback = event.get("coordinator_callback") or {}
            callback_status = callback.get("status")
            if callback_status == "delivered":
                status_code = callback.get("response_status_code")
                coordinator_decision = callback.get("coordinator_decision")
                delivery_note = f"Coordinator delivery succeeded (HTTP {status_code})."
                if coordinator_decision:
                    delivery_note += f" Decision: {coordinator_decision}."
                st.caption(delivery_note)
            elif callback_status == "failed":
                st.warning(callback.get("last_error") or "Coordinator delivery failed.")
                if st.button(
                    "Retry coordinator delivery",
                    key=f"retry-{event_id}",
                    use_container_width=True,
                ):
                    try:
                        api_request(
                            "POST",
                            f"/security-events/{event_id}/coordinator-callback/retry",
                        )
                        st.rerun()
                    except RuntimeError as exc:
                        st.error(str(exc))
            elif callback_status == "pending":
                st.info("Coordinator delivery is pending.")
            return

        target = str(event.get("alert", {}).get("actor", ""))
        if identity.casefold() != target.casefold():
            st.info(f"Waiting for {target}. Switch the demo identity to respond as them.")
            return

        st.caption("Your answer is recorded on this security event for the coordinator.")
        with st.container(key=f"response-actions-{event_id}"):
            columns = st.columns(3)
            for column, decision in zip(columns, DECISIONS):
                button_type = "primary" if decision == "No" else "secondary"
                if column.button(
                    decision,
                    key=f"{event_id}-{decision}",
                    type=button_type,
                    use_container_width=True,
                ):
                    try:
                        api_request(
                            "POST",
                            f"/security-events/{event_id}/human-response",
                            json={"responder": identity, "response": decision},
                        )
                        st.rerun()
                    except RuntimeError as exc:
                        st.error(str(exc))


st.set_page_config(
    page_title="SignalRoom · Security Ops",
    page_icon="💬",
    layout="wide",
    initial_sidebar_state="expanded",
)
inject_styles()

try:
    backend_online = api_request("GET", "/health").get("status") == "ok"
except RuntimeError:
    backend_online = False

with st.sidebar:
    st.markdown('<div class="workspace-brand">◈ SignalRoom</div>', unsafe_allow_html=True)
    st.markdown('<div class="workspace-kicker">Workspace</div>', unsafe_allow_html=True)
    st.markdown("**Hackathon SOC**")
    status_dot = "live-dot" if backend_online else "live-dot offline-dot"
    status_text = "Backend connected" if backend_online else "Backend offline"
    st.markdown(
        f'<div class="member-line"><span class="{status_dot}"></span>{status_text}</div>',
        unsafe_allow_html=True,
    )
    st.divider()
    st.markdown('<div class="workspace-kicker">Channels</div>', unsafe_allow_html=True)
    st.button("#  security-ops", use_container_width=True, disabled=True)
    st.button("#  engineering", use_container_width=True, disabled=True)
    st.button("#  general", use_container_width=True, disabled=True)

    st.markdown('<div class="workspace-kicker">Online · 4</div>', unsafe_allow_html=True)
    for member in DEMO_MEMBERS:
        st.markdown(
            f'<div class="member-line"><span class="member-dot"></span>{member}</div>',
            unsafe_allow_html=True,
        )

    st.divider()
    identity = st.selectbox(
        "Demo identity",
        DEMO_MEMBERS,
        index=0,
        help="This is an MVP identity selector, not authentication.",
    )
    st.caption("Demo mode · no authentication")

header_left, header_right = st.columns([0.82, 0.18], vertical_alignment="center")
with header_left:
    st.markdown('<div class="channel-title"># security-ops</div>', unsafe_allow_html=True)
    st.markdown(
        '<div class="channel-subtitle">Incident context and human verification · 4 members</div>',
        unsafe_allow_html=True,
    )
with header_right:
    if st.button("↻  Refresh", key="refresh-chat", use_container_width=True):
        st.rerun()
st.markdown('<div class="channel-rule"></div>', unsafe_allow_html=True)

if not backend_online:
    st.error(
        f"SignalRoom cannot reach the backend at {BACKEND_URL}. Start it with `make backend`."
    )
    st.stop()

try:
    messages = api_request("GET", "/messages")
except RuntimeError as exc:
    st.error(str(exc))
    st.stop()

if not messages:
    st.markdown(
        '<div class="empty-chat"><strong>No messages yet</strong><br>'
        "Start the security-ops conversation below.</div>",
        unsafe_allow_html=True,
    )
else:
    for chat_message in messages:
        if chat_message.get("kind") == "security_verification":
            render_security_message(chat_message, identity)
            st.write("")
        else:
            render_user_message(chat_message)

if prompt := st.chat_input(f"Message #security-ops as {identity}"):
    try:
        api_request("POST", "/messages", json={"author": identity, "content": prompt})
        st.rerun()
    except RuntimeError as exc:
        st.error(str(exc))
