from __future__ import annotations
import hashlib,hmac,os,re,secrets,sqlite3
from contextlib import asynccontextmanager
from datetime import date,datetime,timezone
from pathlib import Path
from typing import Annotated,Literal
from fastapi import Depends,FastAPI,HTTPException,Query,Request
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel,Field
from starlette.middleware.sessions import SessionMiddleware

ROOT=Path(__file__).resolve().parent
PROJECT=ROOT.parent
STATIC=ROOT/"static"
DB_PATH=Path(os.environ.get("DATABASE_PATH",PROJECT/"data"/"nutrition_menu.db"))
DB_PATH.parent.mkdir(parents=True,exist_ok=True)
SECRET=os.environ.get("APP_SECRET_KEY","dev-only-change-this-secret-before-deploying")
MEALS={"breakfast":"Таңғы ас","lunch":"Түскі ас","snack":"Тіскебасар","dinner":"Кешкі ас"}
DEMO=[
("Сұлы үлпегі","Таңғы ас","Құрғақ сұлы үлпегі",379,13.2,6.5,67.7),("Жұмыртқа","Таңғы ас","Піскен жұмыртқа",155,12.6,10.6,1.1),
("Қарақұмық ботқасы","Дәнді дақылдар","Суға пісірілген",92,3.4,.6,19.9),("Тауық төс еті","Ақуыз","Піскен тауық еті",165,31,3.6,0),
("Албырт балығы","Ақуыз","Піскен балық",206,22.1,12.4,0),("Жасымық","Ақуыз","Піскен жасымық",116,9,.4,20.1),
("Табиғи йогурт","Сүт өнімдері","Қантсыз йогурт",61,3.5,3.3,4.7),("Сүзбе","Сүт өнімдері","Майы 5% сүзбе",121,17,5,3),
("Алма","Жемістер","Қабығымен алма",52,.3,.2,13.8),("Банан","Жемістер","Жаңа піскен банан",89,1.1,.3,22.8),
("Қияр","Көкөністер","Жаңа піскен қияр",15,.7,.1,3.6),("Қызанақ","Көкөністер","Жаңа піскен қызанақ",18,.9,.2,3.9),
("Брокколи","Көкөністер","Буға піскен брокколи",35,2.4,.4,7.2),("Авокадо","Көкөністер","Жаңа піскен авокадо",160,2,14.7,8.5),
("Қоңыр күріш","Дәнді дақылдар","Піскен күріш",123,2.7,1,25.6),("Бадам","Жаңғақтар","Қуырылмаған бадам",579,21.2,49.9,21.6)]
def connect():
    db=sqlite3.connect(DB_PATH,timeout=10);db.row_factory=sqlite3.Row;db.execute("PRAGMA foreign_keys=ON");return db
def hash_password(p):
    salt=secrets.token_hex(16);n=310000
    digest=hashlib.pbkdf2_hmac("sha256",p.encode(),salt.encode(),n).hex()
    return "pbkdf2_sha256$"+str(n)+"$"+salt+"$"+digest
def verify(p,stored):
    try:
        scheme,n,salt,expected=stored.split("$",3)
        actual=hashlib.pbkdf2_hmac("sha256",p.encode(),salt.encode(),int(n)).hex()
        return scheme=="pbkdf2_sha256" and hmac.compare_digest(actual,expected)
    except (ValueError,TypeError):return False
def initialize():
    with connect() as db:
        db.executescript((ROOT/"schema.sql").read_text(encoding="utf-8"))
        if not db.execute("SELECT COUNT(*) FROM foods").fetchone()[0]:
            now=datetime.now(timezone.utc).isoformat()
            db.executemany("""INSERT INTO foods(name,category,description,kcal_100,protein_100,fat_100,carbs_100,source_note,is_active,created_at,updated_at)
            VALUES(?,?,?,?,?,?,?, ?,1,?,?)""",[(*f,"Демо мәні; нақты жапсырманы тексеріңіз.",now,now) for f in DEMO])
@asynccontextmanager
async def lifespan(_):
    if os.environ.get("APP_ENV")=="production" and SECRET.startswith("dev-only-"):raise RuntimeError("Production mode requires APP_SECRET_KEY.")
    initialize();yield
app=FastAPI(title="Дұрыс тамақтану мәзірі",version="1.0",lifespan=lifespan)
app.add_middleware(SessionMiddleware,secret_key=SECRET,session_cookie="as_menu_session",max_age=43200,same_site="lax",https_only=os.environ.get("COOKIE_SECURE","false").lower()=="true")
app.mount("/static",StaticFiles(directory=STATIC),name="static")
@app.get("/",include_in_schema=False)
def home():return FileResponse(STATIC/"index.html")
@app.get("/admin",include_in_schema=False)
def admin():return FileResponse(STATIC/"admin.html")
def get_db():
    db=connect()
    try:yield db
    finally:db.close()
Db=Annotated[sqlite3.Connection,Depends(get_db)]
def check_csrf(req:Request):
    a=req.session.get("csrf","");b=req.headers.get("X-CSRF-Token","")
    if not a or not b or not hmac.compare_digest(a,b):raise HTTPException(403,"Қауіпсіздік кілтін жаңартып, бетті қайта ашыңыз.")
def user(req:Request,db:Db):
    uid=req.session.get("user_id");row=db.execute("SELECT id,email,role FROM users WHERE id=?",(uid,)).fetchone() if uid else None
    if not row:raise HTTPException(401,"Алдымен жүйеге кіріңіз.")
    return dict(row)
def admin_user(u:Annotated[dict,Depends(user)]):
    if u["role"]!="admin":raise HTTPException(403,"Бұл бөлім тек әкімшіге арналған.")
    return u
class Credentials(BaseModel):
    email:str=Field(min_length=3,max_length=190);password:str=Field(min_length=1,max_length=128)
class Registration(BaseModel):
    email:str=Field(min_length=3,max_length=190);password:str=Field(min_length=10,max_length=128)
class FoodData(BaseModel):
    name:str=Field(min_length=2,max_length=190);category:str=Field(min_length=2,max_length=60);description:str=Field(default="",max_length=255)
    kcal_100:float=Field(ge=0,le=1000);protein_100:float=Field(ge=0,le=100);fat_100:float=Field(ge=0,le=100);carbs_100:float=Field(ge=0,le=100)
    source_note:str=Field(min_length=3,max_length=255)
class Active(BaseModel):is_active:bool
class MenuItem(BaseModel):food_id:int=Field(gt=0);meal_type:Literal["breakfast","lunch","snack","dinner"];grams:float=Field(gt=0,le=2000)
class MenuData(BaseModel):menu_date:date;items:list[MenuItem]=Field(max_length=100)
def email_value(s):
    s=s.strip().lower()
    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+",s):raise HTTPException(422,"Электрондық пошта пішімін тексеріңіз.")
    return s
def rotate(req,uid):
    req.session.clear();t=secrets.token_urlsafe(32);req.session.update(user_id=uid,csrf=t);return t
def food_json(r):
    d=dict(r)
    for k in ("kcal_100","protein_100","fat_100","carbs_100"):d[k]=float(d[k])
    d["is_active"]=bool(d.get("is_active",1));return d
def menu_json(db,mid):
    m=db.execute("SELECT * FROM menus WHERE id=?",(mid,)).fetchone()
    if not m:return None
    items=[dict(x) for x in db.execute("""SELECT mi.id,mi.food_id,f.name AS food_name,f.category,mi.meal_type,mi.grams,
    mi.snapshot_kcal_100 AS kcal_100,mi.snapshot_protein_100 AS protein_100,mi.snapshot_fat_100 AS fat_100,mi.snapshot_carbs_100 AS carbs_100
    FROM menu_items mi JOIN foods f ON f.id=mi.food_id WHERE mi.menu_id=?""",(mid,)).fetchall()]
    total={"kcal":0.,"protein":0.,"fat":0.,"carbs":0.}
    for x in items:
        for k in total:total[k]+=float(x["grams"])/100*float(x[k+"_100"])
        x["meal_label"]=MEALS[x["meal_type"]]
    return {**dict(m),"items":items,"totals":total}
@app.get("/api/health")
def health():return {"status":"ok"}
@app.get("/api/auth/csrf")
def get_csrf(req:Request):
    t=req.session.get("csrf")
    if not t:t=secrets.token_urlsafe(32);req.session["csrf"]=t
    return {"csrf_token":t}
@app.post("/api/auth/register",dependencies=[Depends(check_csrf)])
def register(d:Registration,req:Request,db:Db):
    e=email_value(d.email)
    try:
        cur=db.execute("INSERT INTO users(email,password_hash,role,created_at) VALUES(?,?,'user',?)",(e,hash_password(d.password),datetime.now(timezone.utc).isoformat()));db.commit()
    except sqlite3.IntegrityError:raise HTTPException(409,"Бұл пошта тіркелген.")
    return {"user":{"id":cur.lastrowid,"email":e,"role":"user"},"csrf_token":rotate(req,cur.lastrowid)}
@app.post("/api/auth/login",dependencies=[Depends(check_csrf)])
def login(d:Credentials,req:Request,db:Db):
    e=email_value(d.email);r=db.execute("SELECT * FROM users WHERE email=?",(e,)).fetchone()
    if not r or not verify(d.password,r["password_hash"]):raise HTTPException(401,"Пошта немесе құпиясөз қате.")
    return {"user":{"id":r["id"],"email":e,"role":r["role"]},"csrf_token":rotate(req,r["id"])}
@app.get("/api/auth/me")
def me(req:Request,db:Db):
    r=db.execute("SELECT id,email,role FROM users WHERE id=?",(req.session.get("user_id"),)).fetchone()
    if not r:raise HTTPException(401,"Жүйеге кірмегенсіз.")
    return dict(r)
@app.post("/api/auth/logout",dependencies=[Depends(check_csrf)])
def logout(req:Request):req.session.clear();return {"ok":True}
@app.get("/api/foods")
def foods(db:Db,q:str=Query("",max_length=100),category:str=Query("",max_length=60),max_kcal:float|None=Query(None,ge=0),min_protein:float|None=Query(None,ge=0),sort:Literal["name","kcal","protein"]="name"):
    w=["is_active=1"];p=[]
    if q.strip():w.append("(name LIKE ? OR description LIKE ?)");p.extend(["%"+q.strip()+"%"]*2)
    if category.strip():w.append("category=?");p.append(category.strip())
    if max_kcal is not None:w.append("kcal_100<=?");p.append(max_kcal)
    if min_protein is not None:w.append("protein_100>=?");p.append(min_protein)
    order={"name":"name COLLATE NOCASE","kcal":"kcal_100","protein":"protein_100 DESC"}[sort]
    return [food_json(x) for x in db.execute("SELECT * FROM foods WHERE "+" AND ".join(w)+" ORDER BY "+order,p).fetchall()]
@app.get("/api/menus")
def by_date(menu_date:date,db:Db,u:Annotated[dict,Depends(user)]):
    r=db.execute("SELECT id FROM menus WHERE user_id=? AND menu_date=?",(u["id"],menu_date.isoformat())).fetchone()
    return menu_json(db,r["id"]) if r else None
@app.post("/api/menus",dependencies=[Depends(check_csrf)])
def save_menu(d:MenuData,db:Db,u:Annotated[dict,Depends(user)]):
    now=datetime.now(timezone.utc).isoformat()
    with db:
        old=db.execute("SELECT id FROM menus WHERE user_id=? AND menu_date=?",(u["id"],d.menu_date.isoformat())).fetchone()
        if old:mid=old["id"];db.execute("UPDATE menus SET updated_at=? WHERE id=?",(now,mid));db.execute("DELETE FROM menu_items WHERE menu_id=?",(mid,))
        else:mid=db.execute("INSERT INTO menus(user_id,menu_date,created_at,updated_at) VALUES(?,?,?,?)",(u["id"],d.menu_date.isoformat(),now,now)).lastrowid
        for x in d.items:
            f=db.execute("SELECT * FROM foods WHERE id=? AND is_active=1",(x.food_id,)).fetchone()
            if not f:raise HTTPException(422,"Тағам каталогтан табылмады.")
            db.execute("INSERT INTO menu_items(menu_id,food_id,meal_type,grams,snapshot_kcal_100,snapshot_protein_100,snapshot_fat_100,snapshot_carbs_100) VALUES(?,?,?,?,?,?,?,?)",(mid,x.food_id,x.meal_type,x.grams,f["kcal_100"],f["protein_100"],f["fat_100"],f["carbs_100"]))
    return menu_json(db,mid)
@app.get("/api/admin/summary")
def summary(db:Db,_:Annotated[dict,Depends(admin_user)]):
    return {"users":db.execute("SELECT COUNT(*) FROM users WHERE role='user'").fetchone()[0],"foods":db.execute("SELECT COUNT(*) FROM foods WHERE is_active=1").fetchone()[0],"menus":db.execute("SELECT COUNT(*) FROM menus").fetchone()[0]}
@app.get("/api/admin/foods")
def admin_foods(db:Db,_:Annotated[dict,Depends(admin_user)]):return [food_json(r) for r in db.execute("SELECT * FROM foods ORDER BY is_active DESC,name COLLATE NOCASE").fetchall()]
@app.post("/api/admin/foods",dependencies=[Depends(check_csrf)])
def add_food(d:FoodData,db:Db,_:Annotated[dict,Depends(admin_user)]):
    n=datetime.now(timezone.utc).isoformat();c=db.execute("INSERT INTO foods(name,category,description,kcal_100,protein_100,fat_100,carbs_100,source_note,is_active,created_at,updated_at) VALUES(?,?,?,?,?,?,?, ?,1,?,?)",(d.name,d.category,d.description,d.kcal_100,d.protein_100,d.fat_100,d.carbs_100,d.source_note,n,n));db.commit()
    return food_json(db.execute("SELECT * FROM foods WHERE id=?",(c.lastrowid,)).fetchone())
@app.put("/api/admin/foods/{fid}",dependencies=[Depends(check_csrf)])
def edit_food(fid:int,d:FoodData,db:Db,_:Annotated[dict,Depends(admin_user)]):
    c=db.execute("UPDATE foods SET name=?,category=?,description=?,kcal_100=?,protein_100=?,fat_100=?,carbs_100=?,source_note=?,updated_at=? WHERE id=?",(d.name,d.category,d.description,d.kcal_100,d.protein_100,d.fat_100,d.carbs_100,d.source_note,datetime.now(timezone.utc).isoformat(),fid));db.commit()
    if not c.rowcount:raise HTTPException(404,"Тағам табылмады.")
    return food_json(db.execute("SELECT * FROM foods WHERE id=?",(fid,)).fetchone())
@app.patch("/api/admin/foods/{fid}/active",dependencies=[Depends(check_csrf)])
def activate(fid:int,d:Active,db:Db,_:Annotated[dict,Depends(admin_user)]):
    c=db.execute("UPDATE foods SET is_active=?,updated_at=? WHERE id=?",(int(d.is_active),datetime.now(timezone.utc).isoformat(),fid));db.commit()
    if not c.rowcount:raise HTTPException(404,"Тағам табылмады.")
    return {"ok":True}

