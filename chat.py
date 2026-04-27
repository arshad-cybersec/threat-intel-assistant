from fastapi import APIRouter, HTTPException
from app.models.schemas import ChatRequest, ChatResponse
from app.services import claude_service
from app.config import settings

router = APIRouter()


@router.post("/", response_model=ChatResponse)
async def chat(request: ChatRequest):
    """
    Conversational threat intelligence chat.
    Supports multi-turn conversations with full history context.
    """
    try:
        history = [{"role": m.role, "content": m.content} for m in request.history]
        response_text = claude_service.chat(request.message, history)
        return ChatResponse(response=response_text, model=settings.CLAUDE_MODEL)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
