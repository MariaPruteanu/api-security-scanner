from fastapi import FastAPI

app = FastAPI()

# Уязвимый эндпоинт (BOLA)
@app.get("/users/{user_id}")
async def get_user(user_id: int):
    # Нет проверки прав доступа!
    users = {
        1: {"id": 1, "name": "Alice", "email": "alice@test.com"},
        2: {"id": 2, "name": "Bob", "email": "bob@test.com"},
        999999: {"id": 999999, "name": "Admin", "email": "admin@test.com"}
    }
    return users.get(user_id, users[1])  # Уязвимость!

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8080)
