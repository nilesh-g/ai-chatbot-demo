
import streamlit as st
from langchain.chat_models import init_chat_model
from langchain.agents import create_agent
import hashlib
import hmac
import time

def verify_password(password, stored_hash):
    return hmac.compare_digest(hashlib.sha256(password.encode()).hexdigest(), stored_hash)

st.title("Nilesh's Chatbot")

# user authentication
if "authenticated" not in st.session_state:
    st.session_state["authenticated"] = False
# maintain chat history
if "chat_history" not in st.session_state:
    st.session_state["chat_history"] = []
# failed login attempts
if "login_attempts" not in st.session_state:
    st.session_state["login_attempts"] = 0
if st.session_state["login_attempts"] >= 5:
    st.error("Too many failed attempts. Please try later.")
    st.stop()
# timeout after 30 minutes
if "login_time" not in st.session_state:
    st.session_state["login_time"] = time.time()
if time.time() - st.session_state["login_time"] > 1800:
    st.session_state["authenticated"] = False
    st.rerun()
# limit chat history
MAX_MESSAGES = 20

if not st.session_state.authenticated:
    with st.form("login"):
        st.header("Login Form", divider=True)
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        submit = st.form_submit_button("Sign In", type="primary")
    if submit:
        if username == st.secrets["APP_USERNAME"] and verify_password(password, st.secrets["APP_PASSWORD"]):
            st.session_state["authenticated"] = True
            st.rerun()
        else:
            st.error("Invalid username or password")
            st.session_state["login_attempts"] += 1
else:
    llm = init_chat_model(
        st.secrets["LLM_MODEL"],
        model_provider=st.secrets["LLM_PROVIDER"],
        base_url=st.secrets["LLM_BASE_URL"],
        api_key=st.secrets["LLM_API_KEY"]
    )
    agent = create_agent(model=llm, tools=[], system_prompt=st.secrets["SYSTEM_PROMPT"])
    with st.sidebar:
        if st.button("Clear Chat", use_container_width=True, type="secondary"):
            del st.session_state["chat_history"]
            st.rerun()
        if st.button("Sign Out", use_container_width=True, type="secondary"):
            st.session_state["authenticated"] = False
            del st.session_state["chat_history"]
            st.rerun()

    user_input = st.chat_input("Ask anything...")
    if user_input:
        try:
            st.session_state.chat_history.append({"role": "user", "content": user_input})
            response = agent.invoke({"messages": st.session_state.chat_history[-MAX_MESSAGES:]})
            st.session_state.chat_history.append({"role": "assistant", "content": response["messages"][-1].content})
        except Exception as e:
            st.error("Some error occurred. Please try again.")
            st.exception(e)
            if st.session_state.chat_history[-1]["role"] == "user":
                del st.session_state.chat_history[-1]

    for msg in st.session_state.chat_history:
        st.chat_message(msg["role"]).write(msg["content"])
