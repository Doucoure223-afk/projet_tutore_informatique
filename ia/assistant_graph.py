"""A stateless, read-only LangGraph workflow for the local security assistant."""

from __future__ import annotations

from typing import Any, Callable, TypedDict

from langgraph.graph import END, START, StateGraph

from assistant_core import clean_answer, clean_question, context_text, sanitize_context


class AssistantState(TypedDict, total=False):
    question: str
    context: dict[str, Any]
    safe_context: str
    answer: str


def build_assistant_graph(model_call: Callable[[str, str], str]):
    """Compile validate → context-bound LLM → response-validation nodes."""

    def prepare(state: AssistantState) -> dict[str, Any]:
        question = clean_question(state.get("question"))
        context = sanitize_context(state.get("context"))
        return {"question": question, "safe_context": context_text(context)}

    def answer(state: AssistantState) -> dict[str, str]:
        return {"answer": model_call(state["question"], state["safe_context"])}

    def validate(state: AssistantState) -> dict[str, str]:
        return {"answer": clean_answer(state.get("answer"))}

    builder = StateGraph(AssistantState)
    builder.add_node("prepare", prepare)
    builder.add_node("answer", answer)
    builder.add_node("validate", validate)
    builder.add_edge(START, "prepare")
    builder.add_edge("prepare", "answer")
    builder.add_edge("answer", "validate")
    builder.add_edge("validate", END)
    return builder.compile()
