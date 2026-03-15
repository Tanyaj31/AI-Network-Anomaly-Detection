import streamlit as st


def render_sidebar_nav(active: str) -> None:
    """
    Render custom sidebar navigation since built-in multipage nav is disabled.
    active: one of "home", "analyze", "monitor", "models", "about"
    """
    st.sidebar.markdown("### 🧭 Navigation")

    def nav_button(label: str, page: str, key: str):
        is_active = active == page
        if st.sidebar.button(
            label,
            key=key,
            use_container_width=True,
            disabled=is_active,
        ):
            st.switch_page(f"pages/{page}.py")

    nav_button("🏠 Home", "1_home", "nav_home")
    nav_button("📊 Analyze", "2_analyze", "nav_analyze")
    nav_button("📡 Live Monitor", "3_live_monitor", "nav_monitor")
    nav_button("🤖 Models", "4_models", "nav_models")
    nav_button("ℹ️ About", "5_about", "nav_about")
