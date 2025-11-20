from fastapi import FastAPI
from app.api.v1 import auth, users
from app.core.database import Base, engine

Base.metadata.create_all(bind=engine)

app = FastAPI(title="Auth System API")

app.include_router(auth.router)
app.include_router(users.router)


@app.get("/")
def root():
    return {"message": "The Auth-System is running successfully, check out the docs for more information by adding /docs to the URL"}


@app.get("/health")
def health():
    return {"status": "ok"}