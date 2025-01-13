import bcrypt
import uvicorn
from fastapi import FastAPI, Response, Request, WebSocket
from pydantic import EmailStr, SecretStr, BaseModel
import pymysql
from fastapi.responses import HTMLResponse

conection = pymysql.connect(
    host="127.0.0.1",
    user="root",
    password="your-password-here",
    db="vaccines",
    port=3307
)

app = FastAPI()

def verify_password(password: str, hashed_password: str):
    return bcrypt.checkpw(password.encode("utf-8"), hashed_password.encode("utf-8"))

def hash_password(password: str):
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

def set_cookie(response: Response, key: str, value: str):
    response.set_cookie(key=key, value=value, httponly=True)

def hash_cookie(id:int, email: str, password: str):
    value = f"{id}:{email}:{password}"
    return bcrypt.hashpw(value.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

def delete_cookie(response: Response, key: str):
    response.delete_cookie(key=key)

def execute_query(query: str, params: tuple = None):
    try:
        with conection.cursor() as cursor:
            if params:
                cursor.execute(query, params)
            else:
                cursor.execute(query)

            if query.strip().upper().startswith(("INSERT", "UPDATE", "DELETE")):
                conection.commit()
                return {"success": True, "message": "Datos guardados correctamente"}

            result = cursor.fetchall()
            return result
    except Exception as e:
        return {"success": False, "message": str(e)}

class Login(BaseModel):
    email: EmailStr
    password: SecretStr
@app.post("/auth/login")
def login(data: Login, response: Response):
    email = data.email
    password = data.password
    if(not email and not password):
        return {"success": False, "message": "Error al obtener las credenciales"}
    query = "SELECT user_id, name, email, role FROM User WHERE email = %s AND password = %s"
    
    result = execute_query(query, (email, password.get_secret_value()))
    if(len(result) == 0):
        return {"success": False, "message": "Credenciales incorrectas"}
    key_cookie = "session" + result[-1][-1]
    set_cookie(response, key=key_cookie, value=hash_cookie(result[0][0], email, password.get_secret_value()))
    return {"success": True, "message": "Logueado correctamente"}

class UserRegister(BaseModel):
    name: str
    email: EmailStr
    password: SecretStr
    role: str
@app.post("/auth/register_user")
def register(data: UserRegister):
    name = data.name
    email = data.email
    password = data.password
    role = data.role
    if(not name and not email and not password and not role):
        return {"success": False, "message": "Error al obtener las credenciales"}
    query = "INSERT INTO User(name, email, password, role) VALUES(%s,%s,%s,%s)"
    hashed_password = hash_password(password.get_secret_value())
    print(hashed_password)
    result = execute_query(query, (name, email, hashed_password, role))
    return result

class UserDelete(BaseModel):
    user_id: int
@app.delete("/user/delete_user")
def delete_user(data: UserDelete):
    user_id = data.user_id
    query = "DELETE FROM User WHERE user_id = %s"
    result = execute_query(query, (user_id))
    if(result.get("success") == True):
        return { "success": True, "message": "Usuario eliminado correctamente"}
    return { "success": False, "message": "Error al eliminar el usuario"}

def format_json(result:tuple, keys:list):
    if isinstance(result, dict) and not result.get("success", True):
        return result
    json_result = [dict(zip(keys, row)) for row in result]
    return {"data": json_result}

@app.post("/auth/logout")
def logout():
    delete_cookie(response=Response, key="session")

@app.get("/user/get_user")
def get_user():
    query = "SELECT user_id, name, email, role FROM User"
    result = execute_query(query)

    if isinstance(result, dict) and not result.get("success", True):
        return result 

    return format_json(result, ["name", "email", "role"])

@app.get("/alarms/get_history_alarms")
def get_history_alarms():
    query = "SELECT reason_for_alarm, description_alarm, state, created_at FROM Alarm"
    result = execute_query(query)
    return format_json(result, ["reason_for_alarm", "description_alarm", "state", "created_at"])

@app.get("/report/get_report")
def get_report():
    query = "SELECT report_id, reporting_frequency, file_format, esp_name, created_at FROM Report"
    result = execute_query(query)
    return format_json(result, ["report_id", "reporting_frequency", "file_format", "esp_name", "created_at"])

class UserUpdate(BaseModel):
    user_id: int
    name: str
    email: EmailStr
    password: SecretStr
    role: str
@app.put("/user/update_user")
def update_user(data: UserUpdate):
    user_id = data.user_id
    name = data.name
    email = data.email
    password = data.password
    role = data.role
    if(not all([name, email, password, role])):
        return {"success": False, "message": "Error al obtener las credenciales"}
    query = "UPDATE User SET name = %s, email = %s, password = %s, role = %s, created_at = CURRENT_TIMESTAMP WHERE user_id = %s"
    hashed_password = hash_password(password.get_secret_value())
    result = execute_query(query, (name, email, hashed_password, role, user_id))
    return result

@app.get("/auth/session")
def session(request: Request):
    user_allowers = ["administrador", "personal", "transportista"]
    cookie = request.cookies
    if(not cookie):
        return {"success": False, "message": "Sesión no iniciada"}
    
    role = [user for user in user_allowers if cookie.get("session" + user) is not None]
    if(role):
        return {"success": True, "role": role[0]}
    
    return {"success": False, "message": "Sesión no iniciada"}

class ESP32Register(BaseModel):
    esp_code: str
    esp_name: str
    responsible_id: int
    vaccine_id: int

@app.post("/esp/register_esp")
def register_esp(data: ESP32Register):
    esp_code = data.esp_code
    esp_name = data.esp_name
    responsible_id = data.responsible_id
    vaccine_id = data.vaccine_id

    if(not all([esp_code, esp_name, responsible_id, vaccine_id])):
        return {"success": False, "message": "Error al obtener las credenciales"}
    query = "INSERT INTO ESP32(id_esp, name, user_id, vaccine_id, is_active) VALUES(%s,%s,%s,%s,%s)"
    is_active = True
    result = execute_query(query, (esp_code, esp_name, responsible_id, vaccine_id, is_active))
    return result

class VaccineRegister(BaseModel):
    code_vaccine: str
    vaccine_name: str
    vaccine_temperature_min: float
    vaccine_temperature_max: float

@app.post("/vaccine/register_vaccine")
def register_vaccine(data: VaccineRegister):
    code_vaccine = data.code_vaccine
    vaccine_name = data.vaccine_name
    vaccine_temperature_min = data.vaccine_temperature_min
    vaccine_temperature_max = data.vaccine_temperature_max
    if(not all([code_vaccine, vaccine_name, vaccine_temperature_min, vaccine_temperature_max])):
        return {"success": False, "message": "Error al obtener las credenciales"}
    query = "INSERT INTO Vaccine(code_vaccine, name, minimum_temperature, maximium_temperature, is_active) VALUES(%s,%s,%s,%s,%s)"
    is_active = True
    result = execute_query(query, (code_vaccine, vaccine_name, vaccine_temperature_min, vaccine_temperature_max, is_active))
    return result

html = """
<!DOCTYPE html>
<html>
    <head>
        <title>Chat</title>
    </head>
    <body>
        <h1>WebSocket Chat</h1>
        
        <script>
            var ws = new WebSocket("ws://127.0.0.1:8000/alarms/alarm");
            ws.onmessage = async function() {
                const response = await fetch("http://127.0.0.1:8000/alarms/alarm");
                const data = await response.json();
                console.log(data);
            };
        </script>
    </body>
</html>
"""


@app.get("/alarms/alarm")
async def get():
    query = "SELECT reason_for_alarm, description_alarm, state, created_at FROM Alarm"
    result = execute_query(query)
    # return format_json(result, ["reason_for_alarm", "description_alarm", "state", "created_at"])
    return HTMLResponse(html)


@app.websocket("/alarms/alarm")
async def alarm(websocket: WebSocket):
    await websocket.accept()
    while True:
        data = await websocket.receive_text()
        print(data)








if(__name__ == "__main__"):
    uvicorn.run(app, host="0.0.0.0", port=8000)
